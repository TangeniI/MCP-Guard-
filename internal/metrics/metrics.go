// Package metrics exposes gateway counters in the Prometheus text format.
//
// It is written against the format directly rather than the Prometheus
// client library: a handful of counters and one histogram do not justify a
// dependency in a gateway that is meant to stay small enough to audit.
//
// Label values come only from configuration (server names) and from the
// gateway's own fixed vocabulary (decision codes, verdicts). Tool names and
// anything else an agent or server controls are never used as labels.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/TangeniI/MCP-Guard-/internal/proxy"
)

// latencyBuckets are upper bounds, in seconds, for gateway-added latency.
var latencyBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

var help = map[string]string{
	"mcpguard_exchanges_total":           "MCP exchanges handled, by server, message kind and outcome.",
	"mcpguard_tool_calls_total":          "Tool calls, by server and decision code.",
	"mcpguard_denials_total":             "Exchanges refused by the gateway, by decision code.",
	"mcpguard_approvals_total":           "Tool calls sent for human approval, by outcome.",
	"mcpguard_scans_total":               "Tool results and tool lists scanned, by verdict.",
	"mcpguard_quarantined_results_total": "Tool results withheld from the model.",
	"mcpguard_tools_hidden_total":        "Tool definitions removed from tool lists, by reason.",
	"mcpguard_added_latency_seconds":     "Time the gateway added to a forwarded tool call (total minus upstream minus approval wait).",
}

// Metrics accumulates counters. It is safe for concurrent use.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // metric -> rendered labels -> value
	buckets  []uint64                      // cumulative counts per latencyBuckets entry
	count    uint64
	sum      float64
}

// New returns an empty Metrics.
func New() *Metrics {
	return &Metrics{counters: make(map[string]map[string]float64), buckets: make([]uint64, len(latencyBuckets))}
}

func (m *Metrics) add(name string, labels ...string) {
	var b strings.Builder
	for i := 0; i+1 < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", labels[i], escape(labels[i+1]))
	}
	if m.counters[name] == nil {
		m.counters[name] = make(map[string]float64)
	}
	m.counters[name][b.String()]++
}

// escape keeps a label value on one line; %q then handles quotes and
// backslashes the way the exposition format requires.
func escape(v string) string {
	if len(v) > 64 {
		v = v[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, v)
}

// Observe records one finished exchange.
func (m *Metrics) Observe(e proxy.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	outcome := "allowed"
	if e.Denied {
		outcome = "denied"
		m.add("mcpguard_denials_total", "code", e.Code)
	}
	kind := string(e.Message.Kind)
	if kind == "" {
		kind = "none"
	}
	m.add("mcpguard_exchanges_total", "server", e.Server, "kind", kind, "outcome", outcome)

	if e.Message.Method == "tools/call" {
		m.add("mcpguard_tool_calls_total", "server", e.Server, "decision", e.Code)
		if e.UpstreamDuration > 0 {
			added := (e.Duration - e.UpstreamDuration - e.ApprovalWait).Seconds()
			if added < 0 {
				added = 0
			}
			m.count++
			m.sum += added
			for i, bound := range latencyBuckets {
				if added <= bound {
					m.buckets[i]++
				}
			}
		}
	}
	if e.ApprovalID != "" || strings.HasPrefix(e.Code, "approval_") {
		m.add("mcpguard_approvals_total", "outcome", e.Code)
	}
	if e.Scanned {
		verdict := e.ScanVerdict
		if verdict == "" {
			verdict = "clean"
		}
		m.add("mcpguard_scans_total", "verdict", verdict)
	}
	if e.Quarantined && e.Message.Method == "tools/call" {
		m.add("mcpguard_quarantined_results_total")
	}
	for _, hidden := range e.ToolsHidden {
		_, reason, _ := strings.Cut(hidden, ": ")
		m.add("mcpguard_tools_hidden_total", "reason", reason)
	}
}

// ServeHTTP writes the metrics in the Prometheus text exposition format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	names := make([]string, 0, len(help))
	for name := range help {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "mcpguard_added_latency_seconds" {
			continue
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help[name], name)
		series := m.counters[name]
		keys := make([]string, 0, len(series))
		for k := range series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(&b, "%s %g\n", name, series[k])
			} else {
				fmt.Fprintf(&b, "%s{%s} %g\n", name, k, series[k])
			}
		}
		if len(series) == 0 && name == "mcpguard_quarantined_results_total" {
			fmt.Fprintf(&b, "%s 0\n", name)
		}
	}

	const h = "mcpguard_added_latency_seconds"
	fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", h, help[h], h)
	for i, bound := range latencyBuckets {
		fmt.Fprintf(&b, "%s_bucket{le=\"%g\"} %d\n", h, bound, m.buckets[i])
	}
	fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", h, m.count, h, m.sum, h, m.count)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
