// Package stdio lets the gateway front an MCP server that speaks over
// standard input and output, which is how most local MCP servers run.
//
// A Transport starts the server as a child process and presents it to the
// proxy as if it were a Streamable HTTP endpoint: each POSTed JSON-RPC
// request is written to the child's stdin and answered with the matching
// line from its stdout. Everything the gateway does to HTTP upstreams
// (policy, approval, scanning, audit) therefore applies unchanged.
//
// Limits: one child serves every agent of that upstream, as a single MCP
// session; messages the server sends on its own initiative (requests and
// notifications to the client) are dropped, because there is no stream to
// carry them.
package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
)

// maxLineBytes bounds one JSON-RPC message from the child.
const maxLineBytes = 16 << 20

// Transport is an http.RoundTripper backed by a child process.
type Transport struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	logger *slog.Logger

	writeMu sync.Mutex // one message at a time on stdin

	mu              sync.Mutex
	nextID          int64
	pending         map[string]chan json.RawMessage
	initResult      json.RawMessage // the server's first initialize result
	sentInitialized bool            // notifications/initialized has been forwarded
	exited          error           // non-nil once the child has gone
	done            chan struct{}
}

// Start launches argv and returns a Transport for it. The child is killed
// when ctx is cancelled.
func Start(ctx context.Context, argv []string, logger *slog.Logger) (*Transport, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("stdio: empty command")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("stdio: starting %s: %w", argv[0], err)
	}

	t := &Transport{cmd: cmd, stdin: stdin, logger: logger, pending: make(map[string]chan json.RawMessage), done: make(chan struct{})}
	go func() { // the child's log output
		lines := bufio.NewScanner(stderr)
		for lines.Scan() {
			logger.Debug("stdio server stderr", "command", argv[0], "line", lines.Text())
		}
	}()
	go t.read(stdout)
	return t, nil
}

// read routes each response line from the child to the request waiting for it.
func (t *Transport) read(stdout io.Reader) {
	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for lines.Scan() {
		line := bytes.TrimSpace(lines.Bytes())
		if len(line) == 0 {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(line, &fields) != nil {
			t.logger.Warn("stdio server wrote a line that is not JSON; ignored")
			continue
		}
		_, isCall := fields["method"]
		id, hasID := fields["id"]
		if isCall || !hasID {
			continue // server-initiated message: nowhere to deliver it
		}
		t.mu.Lock()
		ch := t.pending[string(id)]
		delete(t.pending, string(id))
		t.mu.Unlock()
		if ch != nil {
			ch <- append(json.RawMessage(nil), line...)
		}
	}
	err := lines.Err()
	if err == nil {
		err = errors.New("stdio server exited")
	}
	_ = t.cmd.Wait()
	t.mu.Lock()
	t.exited = err
	for id, ch := range t.pending {
		close(ch)
		delete(t.pending, id)
	}
	t.mu.Unlock()
	close(t.done)
}

// Close stops the child.
func (t *Transport) Close() error {
	_ = t.stdin.Close()
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	<-t.done
	return nil
}

func (t *Transport) write(msg []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if _, err := t.stdin.Write(append(bytes.TrimSpace(msg), '\n')); err != nil {
		return fmt.Errorf("stdio: writing to server: %w", err)
	}
	return nil
}

func response(req *http.Request, status int, body []byte) *http.Response {
	h := http.Header{}
	if len(body) > 0 {
		h.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status, Status: strconv.Itoa(status) + " " + http.StatusText(status),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return response(req, http.StatusMethodNotAllowed, nil), nil // no stream, no session to delete
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxLineBytes))
	if err != nil {
		return nil, err
	}
	// The stdio framing is one message per line; compact removes any
	// newlines a client put between tokens.
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return nil, fmt.Errorf("stdio: request is not JSON: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(compact.Bytes(), &fields); err != nil {
		return nil, fmt.Errorf("stdio: request is not a JSON object: %w", err)
	}
	var method string
	_ = json.Unmarshal(fields["method"], &method)
	clientID, isRequest := fields["id"]

	t.mu.Lock()
	exited, cachedInit := t.exited, t.initResult
	t.mu.Unlock()
	if exited != nil {
		return nil, exited
	}

	if !isRequest {
		// The child is one session: it is told "initialized" only once.
		if method == "notifications/initialized" {
			t.mu.Lock()
			already := t.initializedSent()
			t.mu.Unlock()
			if already {
				return response(req, http.StatusAccepted, nil), nil
			}
		}
		if err := t.write(compact.Bytes()); err != nil {
			return nil, err
		}
		return response(req, http.StatusAccepted, nil), nil
	}

	// A later agent initializing gets the first answer again: the child
	// cannot be initialized twice.
	if method == "initialize" && cachedInit != nil {
		out, _ := json.Marshal(map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": clientID, "result": cachedInit})
		return response(req, http.StatusOK, out), nil
	}

	// Give the request an ID of our own, so two agents that both count
	// from 1 cannot receive each other's answers.
	t.mu.Lock()
	t.nextID++
	ownID := strconv.FormatInt(t.nextID, 10)
	ch := make(chan json.RawMessage, 1)
	t.pending[ownID] = ch
	t.mu.Unlock()

	fields["id"] = json.RawMessage(ownID)
	out, _ := json.Marshal(fields)
	if err := t.write(out); err != nil {
		t.forget(ownID)
		return nil, err
	}

	select {
	case line, ok := <-ch:
		if !ok {
			return nil, errors.New("stdio server exited before answering")
		}
		var reply map[string]json.RawMessage
		if err := json.Unmarshal(line, &reply); err != nil {
			return nil, err
		}
		reply["id"] = clientID
		if result, isResult := reply["result"]; isResult && method == "initialize" {
			t.mu.Lock()
			if t.initResult == nil {
				t.initResult = result
			}
			t.mu.Unlock()
		}
		restored, _ := json.Marshal(reply)
		return response(req, http.StatusOK, restored), nil
	case <-req.Context().Done():
		t.forget(ownID)
		return nil, req.Context().Err()
	}
}

func (t *Transport) forget(id string) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
}

// initializedSent reports, and records, whether the child has already been
// sent notifications/initialized. Called with t.mu held.
func (t *Transport) initializedSent() bool {
	sent := t.sentInitialized
	t.sentInitialized = true
	return sent
}
