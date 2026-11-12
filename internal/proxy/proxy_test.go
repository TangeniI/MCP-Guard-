package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type eventLog struct {
	mu     sync.Mutex
	events []proxy.Event
}

func (l *eventLog) add(e proxy.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) snapshot() []proxy.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]proxy.Event(nil), l.events...)
}

// connect opens an MCP client session against endpoint using the official SDK.
func connect(t *testing.T, ctx context.Context, endpoint string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		t.Fatalf("connect to %s: %v", endpoint, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool returned an error: %+v", res.Content)
	}
	if len(res.Content) != 1 {
		t.Fatalf("want 1 content block, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("want text content, got %T", res.Content[0])
	}
	return tc.Text
}

// TestPassThrough is the milestone 1 integration test: a real MCP client
// talks to a real MCP server through the gateway and sees exactly what it
// would see talking to the server directly.
func TestPassThrough(t *testing.T) {
	// Servers are closed with t.Cleanup, not defer: cleanups run last-in
	// first-out, so the client sessions opened below close before them.
	upstream := httptest.NewServer(sampleserver.Handler())
	t.Cleanup(upstream.Close)

	var log eventLog
	h, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": mustURL(t, upstream.URL)},
		Logger:     quietLogger(),
		Authorizer: proxy.AllowAll{},
		OnEvent:    log.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(h)
	t.Cleanup(gateway.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	direct := connect(t, ctx, upstream.URL)
	guarded := connect(t, ctx, gateway.URL+"/sample/mcp")

	// The tool list is identical with and without the gateway.
	wantTools, err := direct.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	gotTools, err := guarded.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools through gateway: %v", err)
	}
	wantJSON, _ := json.Marshal(wantTools.Tools)
	gotJSON, _ := json.Marshal(gotTools.Tools)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("tool list changed by gateway:\n got %s\nwant %s", gotJSON, wantJSON)
	}
	if len(gotTools.Tools) != 3 {
		t.Errorf("want 3 tools, got %d", len(gotTools.Tools))
	}

	// A text result passes through, including non-ASCII.
	const msg = "héllo → wörld"
	res, err := guarded.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": msg}})
	if err != nil {
		t.Fatalf("echo through gateway: %v", err)
	}
	if got := text(t, res); got != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}

	// A structured result passes through.
	res, err = guarded.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 2, "b": 40}})
	if err != nil {
		t.Fatalf("add through gateway: %v", err)
	}
	structured, _ := json.Marshal(res.StructuredContent)
	if string(structured) != `{"sum":42}` {
		t.Errorf("add structured content = %s, want {\"sum\":42}", structured)
	}

	// A server-side tool error is the server's answer, not a gateway failure.
	res, err = guarded.CallTool(ctx, &mcp.CallToolParams{Name: "no-such-tool", Arguments: map[string]any{}})
	if err == nil && !res.IsError {
		t.Error("calling an unknown tool should fail")
	}

	// The gateway saw every tool call, with the tool name it will later
	// make decisions on. An exchange is recorded just after its response is
	// sent, so give the last record a moment to land.
	countCalls := func() (n int) {
		for _, e := range log.snapshot() {
			if e.Message.Method == "tools/call" {
				n++
			}
		}
		return n
	}
	for deadline := time.Now().Add(5 * time.Second); countCalls() < 3 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	var calls []string
	for _, e := range log.snapshot() {
		if e.Server != "sample" {
			t.Errorf("event for unexpected server %q", e.Server)
		}
		if e.Denied {
			t.Errorf("gateway denied %s %s: %s", e.Message.Method, e.Message.Tool, e.Reason)
		}
		if e.Message.Method == "tools/call" {
			calls = append(calls, e.Message.Tool)
		}
	}
	if got, want := strings.Join(calls, ","), "echo,add,no-such-tool"; got != want {
		t.Errorf("observed tool calls = %q, want %q", got, want)
	}
}

// TestRejections checks that anything the gateway cannot fully understand is
// refused and never reaches the upstream server.
func TestRejections(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	h, err := proxy.New(proxy.Config{
		Upstreams:    map[string]*url.URL{"sample": mustURL(t, upstream.URL)},
		Logger:       quietLogger(),
		Authorizer:   proxy.AllowAll{},
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(h)
	defer gateway.Close()

	const validCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		headers    map[string]string
		wantStatus int
		wantHit    bool
	}{
		{name: "valid call is forwarded", body: validCall, wantStatus: 200, wantHit: true},
		{name: "matching headers are forwarded", body: validCall,
			headers: map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "echo"}, wantStatus: 200, wantHit: true},
		{name: "base64 header is decoded", body: validCall,
			headers: map[string]string{"Mcp-Name": "=?base64?ZWNobw==?="}, wantStatus: 200, wantHit: true},
		{name: "notification is forwarded", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, wantStatus: 200, wantHit: true},

		{name: "unknown server", path: "/other/mcp", body: validCall, wantStatus: 404},
		{name: "unknown path", path: "/sample/admin", body: validCall, wantStatus: 404},
		{name: "not JSON", body: `tools/call echo`, wantStatus: 400},
		{name: "empty body", body: ``, wantStatus: 400},
		{name: "trailing data", body: validCall + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rm"}}`, wantStatus: 400},
		{name: "batch", body: `[` + validCall + `]`, wantStatus: 400},
		{name: "scalar", body: `"tools/call"`, wantStatus: 400},
		{name: "wrong jsonrpc version", body: `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, wantStatus: 400},
		{name: "method not a string", body: `{"jsonrpc":"2.0","id":1,"method":["tools/call"]}`, wantStatus: 400},
		{name: "duplicate method key",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"echo"}}`, wantStatus: 400},
		{name: "duplicate tool name key",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"delete_everything"}}`, wantStatus: 400},
		{name: "duplicate key via unicode escape",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"delete_everything"}}`, wantStatus: 400},
		{name: "duplicate key deep in arguments",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/workspace/a","path":"/etc/passwd"}}}`, wantStatus: 400},
		{name: "wrong-case method key is not a method",
			body: `{"jsonrpc":"2.0","id":1,"Method":"tools/call"}`, wantStatus: 400},
		{name: "tools/call without params", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, wantStatus: 400},
		{name: "tools/call with non-string name",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{"x":"echo"}}}`, wantStatus: 400},
		{name: "Mcp-Method header disagrees with body", body: validCall,
			headers: map[string]string{"Mcp-Method": "tools/list"}, wantStatus: 400},
		{name: "Mcp-Name header disagrees with body", body: validCall,
			headers: map[string]string{"Mcp-Name": "add"}, wantStatus: 400},
		{name: "body too large", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"` +
			strings.Repeat("a", 2048) + `"}}}`, wantStatus: 413},
		{name: "deep nesting", body: `{"jsonrpc":"2.0","id":1,"method":"x","params":` +
			strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`, wantStatus: 400},
		{name: "foreign browser origin", body: validCall,
			headers: map[string]string{"Origin": "https://evil.example"}, wantStatus: 403},
		{name: "PUT", method: http.MethodPut, body: validCall, wantStatus: 405},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path := tt.method, tt.path
			if method == "" {
				method = http.MethodPost
			}
			if path == "" {
				path = "/sample/mcp"
			}
			req, err := http.NewRequest(method, gateway.URL+path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			before := upstreamHits.Load()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantStatus, body)
			}
			if hit := upstreamHits.Load() > before; hit != tt.wantHit {
				t.Errorf("reached upstream = %v, want %v", hit, tt.wantHit)
			}
			// Every refusal on a known route is a well-formed JSON-RPC error.
			if !tt.wantHit && tt.path == "" {
				var e struct {
					JSONRPC string `json:"jsonrpc"`
					Error   *struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(body, &e); err != nil || e.JSONRPC != "2.0" || e.Error == nil || e.Error.Message == "" {
					t.Errorf("refusal is not a JSON-RPC error: %s", body)
				}
			}
		})
	}
}

func TestUpstreamDown(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	h, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": mustURL(t, deadURL)},
		Logger:     quietLogger(),
		Authorizer: proxy.AllowAll{},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sample/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"id":7`) {
		t.Errorf("error should carry the request id: %s", rec.Body)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	good := mustURL(t, "http://127.0.0.1:9001")
	tests := []struct {
		name      string
		upstreams map[string]*url.URL
	}{
		{"no upstreams", nil},
		{"empty name", map[string]*url.URL{"": good}},
		{"name with slash", map[string]*url.URL{"a/b": good}},
		{"nil url", map[string]*url.URL{"a": nil}},
		{"relative url", map[string]*url.URL{"a": mustURL(t, "/mcp")}},
		{"non-http scheme", map[string]*url.URL{"a": mustURL(t, "file:///etc/passwd")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := proxy.New(proxy.Config{Upstreams: tt.upstreams, Authorizer: proxy.AllowAll{}}); err == nil {
				t.Error("want an error, got nil")
			}
		})
	}
}

func TestNewRequiresAuthorizer(t *testing.T) {
	_, err := proxy.New(proxy.Config{Upstreams: map[string]*url.URL{"a": mustURL(t, "http://127.0.0.1:9001")}})
	if err == nil {
		t.Error("a gateway with no authorizer must not start")
	}
}

type flakyRecorder struct {
	fail  atomic.Bool
	calls atomic.Int64
}

func (f *flakyRecorder) Record(proxy.Event) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("disk full")
	}
	return nil
}

// TestNoAuditNoCalls: when a record cannot be stored, the gateway stops
// forwarding until the log works again.
func TestNoAuditNoCalls(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	rec := &flakyRecorder{}
	h, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": mustURL(t, upstream.URL)},
		Logger:     quietLogger(),
		Authorizer: proxy.AllowAll{},
		Audit:      rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sample/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
		return w.Code
	}
	health := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return w.Code
	}

	if code := post(); code != 200 || upstreamHits.Load() != 1 || health() != 204 {
		t.Fatalf("healthy gateway: status %d, hits %d", code, upstreamHits.Load())
	}

	rec.fail.Store(true)
	post() // this exchange completes, but its record is lost
	for i := 0; i < 3; i++ {
		if code := post(); code != http.StatusServiceUnavailable {
			t.Errorf("with the audit log down: status %d, want 503", code)
		}
	}
	if got := upstreamHits.Load(); got != 2 {
		t.Errorf("upstream was called %d times; calls must stop once the audit log fails", got)
	}
	if health() != http.StatusServiceUnavailable {
		t.Error("healthz should report the audit failure")
	}

	// Recovery: the next refusal is recorded, and service resumes.
	rec.fail.Store(false)
	if code := post(); code != http.StatusServiceUnavailable {
		t.Errorf("first request after recovery: status %d, want 503", code)
	}
	if code := post(); code != 200 || health() != 204 {
		t.Errorf("gateway did not recover: status %d", code)
	}
}
