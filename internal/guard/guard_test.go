package guard_test

import (
	"context"
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

	"github.com/TangeniI/MCP-Guard-/internal/guard"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
)

// The policy lets "alpha" (token test-token-alpha) call echo on the sample
// server and nothing else. "beta" exists but has no servers.
const testPolicy = `
version: 1
agents:
  - name: alpha
    token_sha256: 05272b9d20f61cbfc976ef4e81c93161fd0224f7a4ccb1f5e92dfa7241a61bb5
    servers:
      sample:
        tools:
          echo: {}
  - name: beta
    token_sha256: 09454e35b80939a2d12023fad0ea0f343068522fb530476d6b7f47dd4d2720b5
    servers: {}
`

// bearer adds an Authorization header to every request.
type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

type harness struct {
	gatewayURL   string
	upstreamAuth atomic.Value // last Authorization header seen upstream
	toolCalls    atomic.Int64 // tools/call requests that reached upstream

	mu     sync.Mutex
	events []proxy.Event
}

func (h *harness) snapshot() []proxy.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]proxy.Event(nil), h.events...)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.upstreamAuth.Store("")

	sample := sampleserver.Handler()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			h.upstreamAuth.Store(a)
		}
		if r.Header.Get("Mcp-Method") == "tools/call" {
			h.toolCalls.Add(1)
		} else if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"tools/call"`) {
				h.toolCalls.Add(1)
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		sample.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)

	pol, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": target},
		Authorizer: guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnEvent: func(e proxy.Event) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, e)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(handler)
	t.Cleanup(gateway.Close)
	h.gatewayURL = gateway.URL
	return h
}

func (h *harness) connect(ctx context.Context, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.1"}, nil)
	httpClient := &http.Client{Transport: bearer{token, http.DefaultTransport}}
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   h.gatewayURL + "/sample/mcp",
		HTTPClient: httpClient,
	}, nil)
}

// TestPolicyEndToEnd runs a real MCP client through the gateway with a real
// policy and checks default deny from the agent's point of view.
func TestPolicyEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := h.connect(ctx, "test-token-alpha")
	if err != nil {
		t.Fatalf("alpha could not connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	// Discovery works.
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 3 {
		t.Errorf("want 3 tools listed, got %d", len(tools.Tools))
	}

	// The allowed tool works.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if res.IsError || len(res.Content) != 1 || res.Content[0].(*mcp.TextContent).Text != "hi" {
		t.Errorf("echo returned %+v", res)
	}
	if got := h.toolCalls.Load(); got != 1 {
		t.Errorf("upstream saw %d tool calls after echo, want 1", got)
	}

	// A tool the policy does not list is refused as a failed tool result
	// the model can read, and never reaches the server.
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 1, "b": 2}})
	if err != nil {
		t.Fatalf("a denied call should be a tool error, not a transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("add was not denied: %+v", res)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "Denied by MCP Guard policy") {
		t.Errorf("denial text = %q", text)
	}
	if got := h.toolCalls.Load(); got != 1 {
		t.Errorf("denied call reached upstream (%d tool calls seen)", got)
	}

	// The gateway token is never forwarded to the MCP server.
	if a := h.upstreamAuth.Load().(string); a != "" {
		t.Errorf("Authorization header leaked upstream: %q", a)
	}

	// Every event is attributed to alpha and stamped with a policy version;
	// the only denial is the add call. Events are recorded just after the
	// response is sent, so wait for the last one.
	sawAdd := func() bool {
		for _, e := range h.snapshot() {
			if e.Message.Tool == "add" {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(5 * time.Second); !sawAdd() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	var denied []string
	for _, e := range h.snapshot() {
		if e.Agent != "alpha" || len(e.PolicyVersion) != 64 {
			t.Errorf("event not attributed: %+v", e)
		}
		if e.Denied {
			denied = append(denied, e.Message.Method+" "+e.Message.Tool+" "+e.Code)
		}
	}
	if got, want := strings.Join(denied, "; "), "tools/call add tool_not_allowed"; got != want {
		t.Errorf("denials = %q, want %q", got, want)
	}
}

func TestUnauthenticatedAgentsCannotConnect(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for name, token := range map[string]string{
		"wrong token":             "not-the-token",
		"empty token":             "",
		"known agent, no servers": "test-token-beta",
	} {
		t.Run(name, func(t *testing.T) {
			session, err := h.connect(ctx, token)
			if err == nil {
				_, err = session.ListTools(ctx, nil)
				_ = session.Close()
			}
			if err == nil {
				t.Fatal("connected and listed tools without permission")
			}
		})
	}
	for _, e := range h.snapshot() {
		if !e.Denied {
			t.Errorf("an exchange was allowed: %+v", e)
		}
	}
}
