package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TangeniI/MCP-Guard-/internal/proxy"
)

func TestMetrics(t *testing.T) {
	m := New()
	call := proxy.Message{Kind: proxy.KindRequest, Method: "tools/call", Tool: "secret-tool-name"}
	m.Observe(proxy.Event{Server: "files", Message: call, Code: "allowed", Duration: 3 * time.Millisecond,
		UpstreamDuration: 2 * time.Millisecond, Scanned: true, ScanVerdict: "clean"})
	m.Observe(proxy.Event{Server: "files", Message: call, Code: "allowed", Duration: 40 * time.Millisecond,
		UpstreamDuration: 10 * time.Millisecond, Scanned: true, ScanVerdict: "injection", Quarantined: true})
	m.Observe(proxy.Event{Server: "files", Message: call, Code: "approved", ApprovalID: "a1", Duration: 5 * time.Second,
		UpstreamDuration: time.Millisecond, ApprovalWait: 4990 * time.Millisecond})
	m.Observe(proxy.Event{Server: "files", Message: call, Code: "tool_not_allowed", Denied: true})
	m.Observe(proxy.Event{Server: "files", Message: call, Code: "approval_timeout", Denied: true, ApprovalID: "a2"})
	m.Observe(proxy.Event{Server: "mail", Message: proxy.Message{Kind: proxy.KindRequest, Method: "tools/list"}, Code: "allowed",
		Scanned: true, ToolsHidden: []string{"lookup: tool_poisoned", "read: tool_changed"}})
	m.Observe(proxy.Event{Server: "x\"\n{evil}", Code: "invalid", Denied: true})

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()

	for _, want := range []string{
		`mcpguard_tool_calls_total{server="files",decision="allowed"} 2`,
		`mcpguard_tool_calls_total{server="files",decision="approved"} 1`,
		`mcpguard_tool_calls_total{server="files",decision="tool_not_allowed"} 1`,
		`mcpguard_denials_total{code="tool_not_allowed"} 1`,
		`mcpguard_denials_total{code="approval_timeout"} 1`,
		`mcpguard_approvals_total{outcome="approved"} 1`,
		`mcpguard_approvals_total{outcome="approval_timeout"} 1`,
		`mcpguard_scans_total{verdict="injection"} 1`,
		`mcpguard_scans_total{verdict="clean"} 2`,
		`mcpguard_quarantined_results_total 1`,
		`mcpguard_tools_hidden_total{reason="tool_poisoned"} 1`,
		`mcpguard_tools_hidden_total{reason="tool_changed"} 1`,
		`mcpguard_exchanges_total{server="files",kind="request",outcome="denied"} 2`,
		`mcpguard_exchanges_total{server="x\"_{evil}",kind="none",outcome="denied"} 1`,
		// 1 ms, 30 ms and 9 ms of added time (the approval wait is excluded).
		`mcpguard_added_latency_seconds_bucket{le="0.001"} 1`,
		`mcpguard_added_latency_seconds_bucket{le="0.01"} 2`,
		`mcpguard_added_latency_seconds_bucket{le="0.05"} 3`,
		`mcpguard_added_latency_seconds_bucket{le="+Inf"} 3`,
		`mcpguard_added_latency_seconds_count 3`,
		"# TYPE mcpguard_added_latency_seconds histogram",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing line: %s", want)
		}
	}
	if strings.Contains(out, "secret-tool-name") {
		t.Error("tool names must not appear in metrics")
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.ContainsAny(line, "\r") || line == "" {
			t.Errorf("malformed exposition line %q", line)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("content type = %q", ct)
	}
}
