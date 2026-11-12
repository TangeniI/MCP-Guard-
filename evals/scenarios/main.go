// Command scenarios plays the MCP-specific scenario suite against the real
// gateway code and writes a results file.
//
//	go run ./evals/scenarios            # writes evals/results/scenarios-<date>.json
//
// Each scenario runs four times, once per gateway configuration, so the
// results show which layer does the work:
//
//	off     no policy, no scanning, no pinning (what the agent would get alone)
//	policy  the shared policy in policy.yaml only
//	content rules scanning of results and tool lists, plus tool pinning
//	both    policy and content together
//
// The MCP server is scripted from the scenario; the "agent" is the scenario's
// list of actions. No model is involved: an attack scenario asks whether the
// harmful thing was possible at all, not whether a model would be fooled.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TangeniI/MCP-Guard-/internal/guard"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/scan"
)

//go:embed scenarios.json
var scenariosJSON []byte

//go:embed policy.yaml
var policyYAML []byte

const agentToken = "scenario-agent-token-not-a-secret"

var modes = []string{"off", "policy", "content", "both"}

// Scenario is one story. See generate.py for how they are written.
type Scenario struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Split       string   `json:"split"` // "dev" or "heldout"
	Kind        string   `json:"kind"`  // "attack" or "benign"
	Description string   `json:"description"`
	Actions     []string `json:"actions"` // "list" or "call", in order
	Call        *struct {
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"call"`
	Harm   string `json:"harm"`   // attacks: call_reaches_server | result_reaches_agent | tool_visible
	Marker string `json:"marker"` // text or tool name that identifies the harmful content
	Expect string `json:"expect"` // benign: call_ok | tools_visible
	Server struct {
		Tools      []json.RawMessage `json:"tools"`
		ToolsAfter []json.RawMessage `json:"tools_after"` // served from the second listing
		ToolsFinal []json.RawMessage `json:"tools_final"` // served from the third listing
		Result     string            `json:"result"`
	} `json:"server"`
}

// fakeServer is the scripted MCP server for one scenario run.
type fakeServer struct {
	sc       *Scenario
	listings int
	calls    []string
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &msg)
	var result any
	switch msg.Method {
	case "tools/list":
		tools := f.sc.Server.Tools
		if f.listings >= 1 && f.sc.Server.ToolsAfter != nil {
			tools = f.sc.Server.ToolsAfter
		}
		if f.listings >= 2 && f.sc.Server.ToolsFinal != nil {
			tools = f.sc.Server.ToolsFinal
		}
		f.listings++
		result = map[string]any{"tools": tools}
	case "tools/call":
		f.calls = append(f.calls, msg.Params.Name)
		result = map[string]any{"content": []map[string]string{{"type": "text", "text": f.sc.Server.Result}}}
	default:
		result = map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
}

// newGateway builds the gateway for one mode, in front of upstream.
func newGateway(mode string, upstream *url.URL) (http.Handler, error) {
	cfg := proxy.Config{
		Upstreams:  map[string]*url.URL{"office": upstream},
		Authorizer: proxy.AllowAll{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mode == "policy" || mode == "both" {
		pol, err := policy.Parse(policyYAML)
		if err != nil {
			return nil, err
		}
		cfg.Authorizer = guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)}
	}
	if mode == "content" || mode == "both" {
		scanner, err := scan.New(scan.Options{Rules: true})
		if err != nil {
			return nil, err
		}
		cfg.Scanner = guard.ResultScanner{Scanner: scanner}
		cfg.PinTools = true
	}
	return proxy.New(cfg)
}

// Outcome is what happened to one scenario in one mode.
type Outcome struct {
	Pass   bool   `json:"pass"`   // attack: harm prevented; benign: task worked
	Detail string `json:"detail"` // what was observed
}

func post(gw http.Handler, body string) string {
	req := httptest.NewRequest(http.MethodPost, "/office/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Body.String()
}

func runScenario(sc *Scenario, mode string) (Outcome, error) {
	server := &fakeServer{sc: sc}
	upstream := httptest.NewServer(server)
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	gw, err := newGateway(mode, target)
	if err != nil {
		return Outcome{}, err
	}

	var lastList, lastCall string
	for _, action := range sc.Actions {
		switch action {
		case "list":
			lastList = post(gw, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		case "call":
			args := sc.Call.Arguments
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			name, _ := json.Marshal(sc.Call.Tool)
			lastCall = post(gw, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":`+string(name)+`,"arguments":`+string(args)+`}}`)
		default:
			return Outcome{}, fmt.Errorf("%s: unknown action %q", sc.ID, action)
		}
	}

	visible := map[string]bool{}
	var listed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	_ = json.Unmarshal([]byte(lastList), &listed)
	for _, t := range listed.Result.Tools {
		visible[t.Name] = true
	}
	var called struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	_ = json.Unmarshal([]byte(lastCall), &called)
	callText := ""
	if len(called.Result.Content) > 0 {
		callText = called.Result.Content[0].Text
	}
	reached := sc.Call != nil && contains(server.calls, sc.Call.Tool)

	if sc.Kind == "benign" {
		switch sc.Expect {
		case "call_ok":
			switch {
			case !reached:
				return Outcome{false, "the call was refused: " + clip(callText)}, nil
			case called.Result.IsError || callText != sc.Server.Result:
				return Outcome{false, "the result was withheld or altered: " + clip(callText)}, nil
			}
			return Outcome{true, "call forwarded, result delivered intact"}, nil
		case "tools_visible":
			final := sc.Server.Tools
			if sc.Server.ToolsAfter != nil {
				final = sc.Server.ToolsAfter
			}
			for _, raw := range final {
				var t struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(raw, &t)
				if !visible[t.Name] {
					return Outcome{false, "tool " + t.Name + " was hidden"}, nil
				}
			}
			return Outcome{true, "all tools shown"}, nil
		}
		return Outcome{}, fmt.Errorf("%s: unknown expectation %q", sc.ID, sc.Expect)
	}

	switch sc.Harm {
	case "call_reaches_server":
		if reached {
			return Outcome{false, "the call reached the server"}, nil
		}
		return Outcome{true, "refused: " + clip(callText)}, nil
	case "result_reaches_agent":
		if strings.Contains(callText, sc.Marker) {
			return Outcome{false, "the injected text was delivered to the agent"}, nil
		}
		return Outcome{true, "withheld: " + clip(callText)}, nil
	case "tool_visible":
		if visible[sc.Marker] {
			return Outcome{false, "tool " + sc.Marker + " was shown to the agent"}, nil
		}
		return Outcome{true, "tool " + sc.Marker + " was hidden"}, nil
	}
	return Outcome{}, fmt.Errorf("%s: unknown harm %q", sc.ID, sc.Harm)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 110 {
		s = s[:110] + "…"
	}
	return s
}

// Tally counts passes.
type Tally struct {
	Pass  int `json:"pass"`
	Total int `json:"total"`
}

// Report is the results file.
type Report struct {
	Schema    int    `json:"schema"`
	Suite     string `json:"suite"`
	DateUTC   string `json:"date_utc"`
	Commit    string `json:"guard_commit"`
	Dirty     bool   `json:"uncommitted_changes"`
	Scenarios int    `json:"scenarios"`
	Note      string `json:"note"`
	// Summary[mode][split][group] where group is "attacks blocked",
	// "benign working" or a category name.
	Summary map[string]map[string]map[string]Tally `json:"summary"`
	// Misses in the full configuration ("both"): attacks that got through
	// and benign tasks that broke.
	Misses  []Miss                        `json:"misses_with_both_layers"`
	Results map[string]map[string]Outcome `json:"results"` // scenario id -> mode -> outcome
	Index   []Scenario                    `json:"-"`
}

// Miss is one failure in the full configuration.
type Miss struct {
	ID          string `json:"id"`
	Split       string `json:"split"`
	Category    string `json:"category"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
}

func loadScenarios() ([]Scenario, error) {
	var list []Scenario
	if err := json.Unmarshal(scenariosJSON, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func runAll() (*Report, error) {
	list, err := loadScenarios()
	if err != nil {
		return nil, err
	}
	rep := &Report{
		Schema: 1, Suite: "MCP-specific scenarios", Scenarios: len(list), Index: list,
		Note: "No model is involved. An attack passes when the harmful effect was impossible; a benign " +
			"scenario passes when the task worked unchanged. Rules must never be tuned against heldout scenarios.",
		Summary: map[string]map[string]map[string]Tally{},
		Results: map[string]map[string]Outcome{},
	}
	bump := func(mode, split, group string, pass bool) {
		if rep.Summary[mode] == nil {
			rep.Summary[mode] = map[string]map[string]Tally{}
		}
		if rep.Summary[mode][split] == nil {
			rep.Summary[mode][split] = map[string]Tally{}
		}
		t := rep.Summary[mode][split][group]
		t.Total++
		if pass {
			t.Pass++
		}
		rep.Summary[mode][split][group] = t
	}
	for i := range list {
		sc := &list[i]
		rep.Results[sc.ID] = map[string]Outcome{}
		for _, mode := range modes {
			out, err := runScenario(sc, mode)
			if err != nil {
				return nil, err
			}
			rep.Results[sc.ID][mode] = out
			group := "attacks blocked"
			if sc.Kind == "benign" {
				group = "benign working"
			}
			for _, split := range []string{sc.Split, "all"} {
				bump(mode, split, group, out.Pass)
				bump(mode, split, sc.Category, out.Pass)
			}
			if mode == "both" && !out.Pass {
				rep.Misses = append(rep.Misses, Miss{sc.ID, sc.Split, sc.Category, sc.Kind, sc.Description, out.Detail})
			}
		}
	}
	sort.Slice(rep.Misses, func(i, j int) bool { return rep.Misses[i].ID < rep.Misses[j].ID })
	return rep, nil
}

func git(args ...string) string {
	out, _ := exec.Command("git", args...).Output()
	return strings.TrimSpace(string(out))
}

func main() {
	outDir := flag.String("out", filepath.Join("evals", "results"), "directory for the results file")
	flag.Parse()

	rep, err := runAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		os.Exit(1)
	}
	now := time.Now().UTC()
	rep.DateUTC = now.Format(time.RFC3339)
	rep.Commit = git("rev-parse", "HEAD")
	rep.Dirty = git("status", "--porcelain") != ""

	// A fingerprint of the inputs, so a results file can be matched to them.
	sum := sha256.Sum256(append(append([]byte{}, scenariosJSON...), policyYAML...))
	rep.Note += " Inputs sha256: " + hex.EncodeToString(sum[:8]) + "."

	fmt.Printf("%-8s %-8s %-18s %s\n", "mode", "split", "attacks blocked", "benign working")
	for _, mode := range modes {
		for _, split := range []string{"dev", "heldout", "all"} {
			a, b := rep.Summary[mode][split]["attacks blocked"], rep.Summary[mode][split]["benign working"]
			fmt.Printf("%-8s %-8s %3d / %-12d %3d / %d\n", mode, split, a.Pass, a.Total, b.Pass, b.Total)
		}
	}
	fmt.Printf("\n%d misses with both layers on:\n", len(rep.Misses))
	for _, m := range rep.Misses {
		fmt.Printf("  %-10s %-8s %-7s %s\n", m.ID, m.Split, m.Kind, m.Description)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		os.Exit(1)
	}
	path := filepath.Join(*outDir, "scenarios-"+now.Format("20060102-150405")+".json")
	data, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "scenarios:", err)
		os.Exit(1)
	}
	fmt.Println("\nwrote", path)
}
