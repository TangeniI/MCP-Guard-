package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// JSON-RPC and MCP error codes used by the gateway.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
	codeHeaderMismatch = -32020 // MCP 2026-07-28: header disagrees with body
	codeUpstreamError  = -32000 // gateway-defined: upstream unreachable
)

// maxJSONDepth bounds nesting so a hostile body cannot exhaust the stack.
const maxJSONDepth = 128

// Kind classifies a JSON-RPC message.
type Kind string

const (
	KindRequest      Kind = "request"
	KindNotification Kind = "notification"
	KindResponse     Kind = "response"
)

// Message is what the gateway understood from one JSON-RPC message. Anything
// the gateway will later make a decision on must come from here, never from a
// second, looser parse.
type Message struct {
	Kind   Kind
	Method string          // empty for responses
	ID     json.RawMessage // nil for notifications
	Tool   string          // params.name, set only for tools/call
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return e.Message }

// inspect parses a POST body as exactly one JSON-RPC 2.0 message.
//
// It is deliberately stricter than encoding/json so that the gateway and the
// upstream server cannot disagree about what a message says:
//   - duplicate object keys are rejected at every depth (parsers differ on
//     whether the first or the last one wins);
//   - keys are matched exactly ("Method" is not "method");
//   - batches are rejected, so one POST is always one decision.
func inspect(body []byte) (Message, *rpcError) {
	if err := checkStrictJSON(body); err != nil {
		return Message{}, &rpcError{codeParseError, "parse error: " + err.Error()}
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		// Valid JSON that is not an object: an array (batch) or a scalar.
		if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("[")) {
			return Message{}, &rpcError{codeInvalidRequest, "JSON-RPC batches are not accepted; send one message per request"}
		}
		return Message{}, &rpcError{codeInvalidRequest, "JSON-RPC message must be an object"}
	}

	var m Message
	if id, ok := fields["id"]; ok {
		m.ID = id
	}

	var version string
	if err := json.Unmarshal(fields["jsonrpc"], &version); err != nil || version != "2.0" {
		return m, &rpcError{codeInvalidRequest, `"jsonrpc" must be "2.0"`}
	}

	rawMethod, hasMethod := fields["method"]
	if !hasMethod {
		_, hasResult := fields["result"]
		_, hasError := fields["error"]
		if hasResult == hasError || m.ID == nil {
			return m, &rpcError{codeInvalidRequest, "message is neither a request, a notification nor a response"}
		}
		m.Kind = KindResponse
		return m, nil
	}
	if err := json.Unmarshal(rawMethod, &m.Method); err != nil || m.Method == "" {
		return m, &rpcError{codeInvalidRequest, `"method" must be a non-empty string`}
	}
	if m.ID == nil {
		m.Kind = KindNotification
	} else {
		m.Kind = KindRequest
	}

	if m.Method == "tools/call" {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(fields["params"], &params); err != nil {
			return m, &rpcError{codeInvalidParams, "tools/call requires an object \"params\""}
		}
		if err := json.Unmarshal(params["name"], &m.Tool); err != nil || m.Tool == "" {
			return m, &rpcError{codeInvalidParams, "tools/call requires a non-empty string \"params.name\""}
		}
	}
	return m, nil
}

// checkStrictJSON verifies that data is a single well-formed JSON value with
// no duplicate object keys, bounded nesting and nothing after it.
func checkStrictJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("nesting deeper than %d", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("unexpected end of input")
		}
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected %q", delim)
	}
	_, err = dec.Token() // closing delimiter
	return err
}

// decodeHeaderValue undoes the MCP header encoding for values that are not
// plain visible ASCII: =?base64?<payload>?=
func decodeHeaderValue(v string) (string, error) {
	const prefix, suffix = "=?base64?", "?="
	if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, suffix) || len(v) < len(prefix)+len(suffix) {
		return v, nil
	}
	raw, err := base64.StdEncoding.DecodeString(v[len(prefix) : len(v)-len(suffix)])
	if err != nil {
		return "", fmt.Errorf("invalid base64 header value: %w", err)
	}
	return string(raw), nil
}

// checkHeaders enforces that the routing headers introduced in MCP 2026-07-28
// agree with the body. The gateway decides on the body; a server or another
// intermediary might route on the headers, so a disagreement is refused.
// Headers that are absent (older protocol revisions) are not required here.
func checkHeaders(get func(string) string, m Message) *rpcError {
	if h := get("Mcp-Method"); h != "" {
		v, err := decodeHeaderValue(h)
		if err != nil || v != m.Method {
			return &rpcError{codeHeaderMismatch, "Mcp-Method header does not match the request body"}
		}
	}
	if h := get("Mcp-Name"); h != "" && m.Method == "tools/call" {
		v, err := decodeHeaderValue(h)
		if err != nil || v != m.Tool {
			return &rpcError{codeHeaderMismatch, "Mcp-Name header does not match the request body"}
		}
	}
	return nil
}
