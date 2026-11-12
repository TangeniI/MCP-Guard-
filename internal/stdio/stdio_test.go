package stdio_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
	"github.com/TangeniI/MCP-Guard-/internal/stdio"
)

// The test binary doubles as the stdio MCP server: when re-run with this
// variable set it serves the sample tools on stdin/stdout and exits.
func TestMain(m *testing.M) {
	if os.Getenv("MCPGUARD_TEST_STDIO_SERVER") == "1" {
		if err := sampleserver.RunStdio(context.Background()); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func startGateway(t *testing.T) (*stdio.Transport, string) {
	t.Helper()
	t.Setenv("MCPGUARD_TEST_STDIO_SERVER", "1")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport, err := stdio.Start(ctx, []string{os.Args[0]}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Close() })

	placeholder, _ := url.Parse("http://stdio.invalid/mcp")
	h, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"local": placeholder},
		Transports: map[string]http.RoundTripper{"local": transport},
		Authorizer: proxy.AllowAll{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(h)
	t.Cleanup(gateway.Close)
	return transport, gateway.URL + "/local/mcp"
}

func connect(t *testing.T, ctx context.Context, endpoint string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return session
}

// TestStdioServerBehindGateway: a real MCP client reaches a stdio MCP
// server through the gateway's HTTP endpoint.
func TestStdioServerBehindGateway(t *testing.T) {
	transport, endpoint := startGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two agents, one after the other and then interleaved, share the child.
	first := connect(t, ctx, endpoint)
	second := connect(t, ctx, endpoint)
	for i, session := range []*mcp.ClientSession{first, second, first} {
		tools, err := session.ListTools(ctx, nil)
		if err != nil || len(tools.Tools) != 3 {
			t.Fatalf("agent %d ListTools: %v (%d tools)", i, err, len(tools.Tools))
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "line one\nline two"}})
		if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != "line one\nline two" {
			t.Fatalf("agent %d echo: %v %+v", i, err, res)
		}
	}
	_ = first.Close()
	_ = second.Close()

	// When the server dies the gateway reports an upstream failure.
	transport.Close()
	resp, err := http.Post(endpoint, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("after the server exited: status %d, want 502", resp.StatusCode)
	}
}

func TestStartRejectsBadCommands(t *testing.T) {
	for _, argv := range [][]string{nil, {""}, {"/nonexistent/mcp-server-binary"}} {
		if _, err := stdio.Start(context.Background(), argv, nil); err == nil {
			t.Errorf("Start(%q) succeeded", argv)
		}
	}
}
