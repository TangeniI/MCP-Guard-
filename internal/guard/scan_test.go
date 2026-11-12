package guard_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TangeniI/MCP-Guard-/internal/audit"
	"github.com/TangeniI/MCP-Guard-/internal/guard"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
	"github.com/TangeniI/MCP-Guard-/internal/scan"
)

const scanPolicy = `
version: 1
agents:
  - name: alpha
    token_sha256: 05272b9d20f61cbfc976ef4e81c93161fd0224f7a4ccb1f5e92dfa7241a61bb5
    servers:
      sample:
        tools:
          read_note: {}
`

// TestQuarantineEndToEnd: a real MCP client reads a clean note and a
// poisoned one through the gateway with the rules scanner on. The poisoned
// text never reaches the client.
func TestQuarantineEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(sampleserver.Handler())
	t.Cleanup(upstream.Close)

	pol, err := policy.Parse([]byte(scanPolicy))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	scanner, err := scan.New(scan.Options{Rules: true})
	if err != nil {
		t.Fatal(err)
	}

	target, _ := url.Parse(upstream.URL)
	handler, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": target},
		Authorizer: guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)},
		Scanner:    guard.ResultScanner{Scanner: scanner},
		Audit:      guard.AuditRecorder{Log: log},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(handler)
	t.Cleanup(gateway.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   gateway.URL + "/sample/mcp",
		HTTPClient: &http.Client{Transport: bearer{"test-token-alpha", http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	read := func(id string) (string, bool) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "read_note", Arguments: map[string]any{"id": id}})
		if err != nil {
			t.Fatalf("read_note %s: %v", id, err)
		}
		return res.Content[0].(*mcp.TextContent).Text, res.IsError
	}

	if text, isError := read("welcome"); isError || !strings.HasPrefix(text, "Welcome to the team") {
		t.Errorf("clean note was altered: %q", text)
	}
	text, isError := read("poisoned")
	if !isError || !strings.Contains(text, "was withheld") {
		t.Errorf("poisoned note was not quarantined: %q", text)
	}
	for _, leaked := range []string{"ignore all previous", "1337", "Meeting moved"} {
		if strings.Contains(text, leaked) {
			t.Errorf("quarantine notice leaks %q", leaked)
		}
	}

	h := &approvalHarness{log: log}
	records := h.toolRecords(t, 2)
	if len(records) != 2 {
		t.Fatalf("want 2 tool records, got %d", len(records))
	}
	clean, bad := records[0], records[1]
	if !clean.Scanned || clean.Quarantined || clean.ScanVerdict != "clean" || clean.ScanSource != "rules" {
		t.Errorf("clean record = %+v", clean)
	}
	if !bad.Scanned || !bad.Quarantined || bad.ScanVerdict != "injection" || bad.ScanRule == "" ||
		bad.ScanDetail == "" || len(bad.ResultSHA256) != 64 || !bad.Allowed {
		t.Errorf("quarantined record = %+v", bad)
	}
}
