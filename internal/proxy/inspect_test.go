package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProxyDoesNotImportPolicy is the architecture check: the data path may
// only reach policy through the Authorizer interface.
func TestProxyDoesNotImportPolicy(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue // tests may wire things together
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "/internal/policy") || strings.Contains(path, "/internal/guard") {
				t.Errorf("%s imports %s; the proxy must not depend on policy", name, path)
			}
		}
	}
}

// FuzzInspect: the message parser must never panic, and whatever it accepts
// must be unambiguous.
func FuzzInspect(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"a","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":[1]}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"a":{"a":{"a":[[[{}]]]}}}`,
		``, `{`, `nul`, "\xff\xfe",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		m, rpcErr := inspect(body)
		if rpcErr != nil {
			if rpcErr.Message == "" || rpcErr.Code == 0 {
				t.Fatalf("rejection without code or message: %+v", rpcErr)
			}
			return
		}
		if !json.Valid(body) {
			t.Fatal("accepted a body that is not valid JSON")
		}
		if err := checkStrictJSON(body); err != nil {
			t.Fatalf("accepted a body that fails the strict check: %v", err)
		}
		switch m.Kind {
		case KindRequest:
			if m.Method == "" || m.ID == nil {
				t.Fatalf("request without method or id: %+v", m)
			}
		case KindNotification:
			if m.Method == "" || m.ID != nil {
				t.Fatalf("bad notification: %+v", m)
			}
		case KindResponse:
			if m.Method != "" || m.ID == nil {
				t.Fatalf("bad response: %+v", m)
			}
		default:
			t.Fatalf("accepted message with kind %q", m.Kind)
		}
		if (m.Method == "tools/call") != (m.Tool != "") {
			t.Fatalf("tool name and method disagree: %+v", m)
		}
		if m.Arguments != nil {
			if m.Method != "tools/call" {
				t.Fatalf("arguments on a non-tool message: %+v", m)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(m.Arguments, &obj); err != nil {
				t.Fatalf("accepted arguments that are not an object: %s", m.Arguments)
			}
			if !bytes.Contains(body, m.Arguments) {
				t.Fatal("arguments are not a verbatim slice of the body")
			}
		}
	})
}

// FuzzScanEventStream: the SSE filter must never panic, and with a scanner
// that rejects everything no JSON-RPC result may come out unreplaced.
func FuzzScanEventStream(f *testing.F) {
	for _, s := range []string{
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"SECRET\"}]}}\n\n",
		"event: message\r\nid: 3\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n",
		"data: {\"id\":1,\ndata: \"result\":\"SECRET\"}\n\n", ": comment\n\n", "data\n\n", "", "data: [1,2\n",
		"data: {\"id\":1,\"result\":\"SECRET\"}\r\rdata: {\"id\":1,\"result\":\"SECRET\"}\r\r",
		"data: x\rdata: {\"id\":1,\"result\":\"SECRET\"}",
	} {
		f.Add([]byte(s))
	}
	h := &Handler{cfg: Config{Scanner: rejectAll{}}}
	f.Fuzz(func(t *testing.T, stream []byte) {
		st := &exchange{msg: Message{Kind: KindRequest, Method: "tools/call", Tool: "t", ID: json.RawMessage("1")}}
		out := h.scanEventStream(context.Background(), st, bytes.NewReader(stream), h.scanMessage)
		// Read the output the way the most lenient client would: CRLF, LF
		// and bare CR all end a line.
		out = bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
		out = bytes.ReplaceAll(out, []byte("\r"), []byte("\n"))
		for _, block := range bytes.Split(out, []byte("\n\n")) {
			var data []string
			for _, line := range strings.Split(string(block), "\n") {
				if v, ok := strings.CutPrefix(line, "data:"); ok {
					data = append(data, strings.TrimPrefix(v, " "))
				}
			}
			joined := strings.Join(data, "\n")
			if isRPCResponse(joined) && !strings.Contains(joined, "was withheld") {
				t.Fatalf("a response passed a scanner that rejects everything: %q", joined)
			}
		}
	})
}

type rejectAll struct{}

func (rejectAll) ScanResult(context.Context, ScanInput) ScanOutcome { return ScanOutcome{} }
