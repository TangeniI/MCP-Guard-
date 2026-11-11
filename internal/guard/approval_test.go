package guard_test

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/TangeniI/MCP-Guard-/internal/approval"
	"github.com/TangeniI/MCP-Guard-/internal/audit"
	"github.com/TangeniI/MCP-Guard-/internal/guard"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
)

// alpha may call echo freely; add needs a human.
const approvalPolicy = `
version: 1
agents:
  - name: alpha
    token_sha256: 05272b9d20f61cbfc976ef4e81c93161fd0224f7a4ccb1f5e92dfa7241a61bb5
    servers:
      sample:
        tools:
          echo: {}
          add:
            requires_approval: true
`

type approvalHarness struct {
	broker  *approval.Broker
	log     *audit.Log
	session *mcp.ClientSession
}

func newApprovalHarness(t *testing.T, timeout time.Duration, withApprover bool) *approvalHarness {
	t.Helper()
	upstream := httptest.NewServer(sampleserver.Handler())
	t.Cleanup(upstream.Close)

	pol, err := policy.Parse([]byte(approvalPolicy))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	h := &approvalHarness{broker: approval.NewBroker(timeout, 0), log: log}
	target, _ := url.Parse(upstream.URL)
	cfg := proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": target},
		Authorizer: guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)},
		Audit:      guard.AuditRecorder{Log: log},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if withApprover {
		cfg.Approver = guard.BrokerApprover{Broker: h.broker}
	}
	handler, err := proxy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(handler)
	t.Cleanup(gateway.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.1"}, nil)
	h.session, err = client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   gateway.URL + "/sample/mcp",
		HTTPClient: &http.Client{Transport: bearer{"test-token-alpha", http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.session.Close() })
	return h
}

type callResult struct {
	res *mcp.CallToolResult
	err error
}

// callAdd starts add(2, 40) in the background.
func (h *approvalHarness) callAdd() <-chan callResult {
	done := make(chan callResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, err := h.session.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 2, "b": 40}})
		done <- callResult{res, err}
	}()
	return done
}

func (h *approvalHarness) waitPending(t *testing.T) approval.Request {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if p := h.broker.Pending(); len(p) == 1 {
			return p[0]
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the call never reached the approval queue")
	return approval.Request{}
}

func finish(t *testing.T, done <-chan callResult) *mcp.CallToolResult {
	t.Helper()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("call failed at the transport level: %v", r.err)
		}
		return r.res
	case <-time.After(15 * time.Second):
		t.Fatal("call did not return")
		return nil
	}
}

func denialText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("call was not refused: %+v", res)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

// auditRecords returns the audit records for tools/call, in order.
func (h *approvalHarness) toolRecords(t *testing.T) []audit.Record {
	t.Helper()
	var buf bytes.Buffer
	if _, err := h.log.Export(&buf); err != nil {
		t.Fatalf("audit export: %v", err)
	}
	var out []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		var r audit.Record
		if err := json.Unmarshal(e.Record, &r); err != nil {
			t.Fatal(err)
		}
		if r.Agent != "alpha" || len(r.PolicyVersion) != 64 || r.Status == 0 || r.DurationUS <= 0 {
			t.Errorf("audit record is incomplete: %+v", r)
		}
		if r.RPCMethod == "tools/call" {
			out = append(out, r)
		}
	}
	return out
}

func TestApprovalEndToEnd(t *testing.T) {
	h := newApprovalHarness(t, time.Minute, true)
	ctx := context.Background()

	// A tool that needs no approval is not held up.
	res, err := h.session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || res.IsError {
		t.Fatalf("echo: %v %+v", err, res)
	}
	if n := len(h.broker.Pending()); n != 0 {
		t.Fatalf("echo queued %d approvals", n)
	}

	// Approved: the human sees the real arguments, and the call runs.
	done := h.callAdd()
	req := h.waitPending(t)
	if req.Agent != "alpha" || req.Server != "sample" || req.Tool != "add" {
		t.Errorf("queued request = %+v", req)
	}
	var shown map[string]float64
	if err := json.Unmarshal(req.Arguments, &shown); err != nil || shown["a"] != 2 || shown["b"] != 40 {
		t.Errorf("arguments shown to the approver = %s", req.Arguments)
	}
	select {
	case <-done:
		t.Fatal("the call returned before anyone approved it")
	case <-time.After(50 * time.Millisecond):
	}
	if err := h.broker.Resolve(req.ID, true, "alice"); err != nil {
		t.Fatal(err)
	}
	res = finish(t, done)
	if structured, _ := json.Marshal(res.StructuredContent); res.IsError || string(structured) != `{"sum":42}` {
		t.Errorf("approved call returned %+v", res)
	}

	// Denied: the agent is told, the server is not called.
	done = h.callAdd()
	req = h.waitPending(t)
	if err := h.broker.Resolve(req.ID, false, "bob"); err != nil {
		t.Fatal(err)
	}
	if text := denialText(t, finish(t, done)); !strings.Contains(text, "human reviewer denied") {
		t.Errorf("denial text = %q", text)
	}

	// The audit log tells the whole story.
	records := h.toolRecords(t)
	if len(records) != 3 {
		t.Fatalf("want 3 tool-call records, got %d", len(records))
	}
	echo, approved, denied := records[0], records[1], records[2]
	if echo.Tool != "echo" || !echo.Allowed || echo.Code != "allowed" || echo.ApprovalID != "" {
		t.Errorf("echo record = %+v", echo)
	}
	if approved.Tool != "add" || !approved.Allowed || approved.Code != "approved" || approved.ApprovedBy != "alice" ||
		approved.ApprovalID == "" || approved.ApprovalWaitUS < 50_000 || approved.UpstreamUS <= 0 {
		t.Errorf("approved record = %+v", approved)
	}
	if denied.Tool != "add" || denied.Allowed || denied.Code != "approval_denied" || denied.ApprovedBy != "bob" || denied.UpstreamUS != 0 {
		t.Errorf("denied record = %+v", denied)
	}
	if n, err := h.log.Verify(); err != nil || n < 3 {
		t.Errorf("audit chain: n=%d err=%v", n, err)
	}
}

func TestApprovalTimeoutIsDenial(t *testing.T) {
	h := newApprovalHarness(t, 100*time.Millisecond, true)
	text := denialText(t, finish(t, h.callAdd()))
	if !strings.Contains(text, "no human approved") {
		t.Errorf("denial text = %q", text)
	}
	records := h.toolRecords(t)
	if len(records) != 1 || records[0].Allowed || records[0].Code != "approval_timeout" || records[0].UpstreamUS != 0 {
		t.Errorf("records = %+v", records)
	}
}

func TestNoApproverIsDenial(t *testing.T) {
	h := newApprovalHarness(t, time.Minute, false)
	text := denialText(t, finish(t, h.callAdd()))
	if !strings.Contains(text, "no approver is configured") {
		t.Errorf("denial text = %q", text)
	}
	records := h.toolRecords(t)
	if len(records) != 1 || records[0].Allowed || records[0].Code != "approval_unavailable" {
		t.Errorf("records = %+v", records)
	}
}
