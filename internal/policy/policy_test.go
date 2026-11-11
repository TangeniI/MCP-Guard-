package policy

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	alphaHash = "05272b9d20f61cbfc976ef4e81c93161fd0224f7a4ccb1f5e92dfa7241a61bb5"
	betaHash  = "09454e35b80939a2d12023fad0ea0f343068522fb530476d6b7f47dd4d2720b5"
)

// minimal returns a valid policy with the given YAML spliced in as the body
// of alpha's "files" server.
func minimal(serverBody string) string {
	return "version: 1\nagents:\n  - name: alpha\n    token_sha256: " + alphaHash +
		"\n    servers:\n      files:\n" + indent(serverBody, 8)
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(minimal(`
tools:
  read_file: {}
  send:
    rate_limit: {per_minute: 5}
    allow_other_arguments: true
    arguments:
      to: {email_domain: example.com}
      path: {path_under: /workspace, max_length: 200}
      mode: {one_of: [fast, 2, true]}
      id: {pattern: "^[a-z]+$"}
`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hash()) != 64 {
		t.Errorf("hash = %q, want 64 hex characters", p.Hash())
	}
	send := p.Agents[0].Servers["files"].Tools["send"]
	if send.Arguments["id"].Regexp == nil {
		t.Error("pattern was not compiled")
	}
	if send.RateLimit.PerMinute != 5 || !send.AllowOtherArguments {
		t.Errorf("tool decoded wrongly: %+v", send)
	}
}

// TestParseInvalid: every one of these must stop startup.
func TestParseInvalid(t *testing.T) {
	agent := func(name, hash string) string {
		return "  - name: " + name + "\n    token_sha256: " + hash + "\n    servers: {}\n"
	}
	tests := map[string]string{
		"empty":                    "",
		"only a comment":           "# nothing\n",
		"not YAML":                 "version: [1\n",
		"scalar":                   "hello",
		"list at top":              "- version: 1\n",
		"missing version":          "agents:\n" + agent("a", alphaHash),
		"wrong version":            "version: 2\nagents:\n" + agent("a", alphaHash),
		"version as string":        "version: \"1\"\nagents:\n" + agent("a", alphaHash),
		"missing agents":           "version: 1\n",
		"no agents":                "version: 1\nagents: []\n",
		"unknown top-level key":    "version: 1\ndefault: allow\nagents:\n" + agent("a", alphaHash),
		"duplicate top-level key":  "version: 1\nversion: 1\nagents:\n" + agent("a", alphaHash),
		"duplicate agent name":     "version: 1\nagents:\n" + agent("a", alphaHash) + agent("a", betaHash),
		"shared token":             "version: 1\nagents:\n" + agent("a", alphaHash) + agent("b", alphaHash),
		"bad agent name":           "version: 1\nagents:\n" + agent("\"a b\"", alphaHash),
		"token not a hash":         "version: 1\nagents:\n" + agent("a", "test-token-alpha"),
		"upper-case hash":          "version: 1\nagents:\n" + agent("a", strings.ToUpper(alphaHash)),
		"missing servers":          "version: 1\nagents:\n  - name: a\n    token_sha256: " + alphaHash + "\n",
		"bad server name":          "version: 1\nagents:\n  - name: a\n    token_sha256: " + alphaHash + "\n    servers:\n      \"a/b\": {}\n",
		"null server":              "version: 1\nagents:\n  - name: a\n    token_sha256: " + alphaHash + "\n    servers:\n      files:\n",
		"unknown server key":       minimal("allow_all: true\n"),
		"tools as list":            minimal("tools: [read_file]\n"),
		"null tool":                minimal("tools:\n  read_file:\n"),
		"duplicate tool":           minimal("tools:\n  read_file: {}\n  read_file: {}\n"),
		"unknown tool key":         minimal("tools:\n  read_file: {allow: true}\n"),
		"misspelt approval key":    minimal("tools:\n  rm: {require_approval: true}\n"),
		"approval not a boolean":   minimal("tools:\n  rm: {requires_approval: \"yes\"}\n"),
		"tools/call as a method":   minimal("methods: [tools/call]\n"),
		"empty method":             minimal("methods: [\"\"]\n"),
		"zero rate limit":          minimal("tools:\n  t: {rate_limit: {per_minute: 0}}\n"),
		"negative rate limit":      minimal("tools:\n  t: {rate_limit: {per_minute: -1}}\n"),
		"fractional rate limit":    minimal("tools:\n  t: {rate_limit: {per_minute: 1.5}}\n"),
		"rate limit without value": minimal("tools:\n  t: {rate_limit: {}}\n"),
		"allow_other without args": minimal("tools:\n  t: {allow_other_arguments: true}\n"),
		"empty constraint":         minimal("tools:\n  t: {arguments: {path: {}}}\n"),
		"unknown constraint":       minimal("tools:\n  t: {arguments: {path: {starts_with: /workspace}}}\n"),
		"bad regexp":               minimal("tools:\n  t: {arguments: {id: {pattern: \"([a-z\"}}}\n"),
		"relative path_under":      minimal("tools:\n  t: {arguments: {path: {path_under: workspace}}}\n"),
		"path_under with dot-dot":  minimal("tools:\n  t: {arguments: {path: {path_under: /workspace/../etc}}}\n"),
		"path_under trailing /":    minimal("tools:\n  t: {arguments: {path: {path_under: /workspace/}}}\n"),
		"email_domain with @":      minimal("tools:\n  t: {arguments: {to: {email_domain: \"@example.com\"}}}\n"),
		"email_domain leading dot": minimal("tools:\n  t: {arguments: {to: {email_domain: .example.com}}}\n"),
		"equals a list":            minimal("tools:\n  t: {arguments: {x: {equals: [1]}}}\n"),
		"equals null":              minimal("tools:\n  t: {arguments: {x: {equals: null}}}\n"),
		"empty one_of":             minimal("tools:\n  t: {arguments: {x: {one_of: []}}}\n"),
		"negative max_length":      minimal("tools:\n  t: {arguments: {x: {max_length: -1}}}\n"),
		"too large":                "version: 1\n#" + strings.Repeat("x", MaxPolicyBytes) + "\n",
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if p, err := Parse([]byte(doc)); err == nil {
				t.Errorf("Parse accepted an invalid policy: %+v", p)
			}
		})
	}
}

func TestExamplePolicyIsValid(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	d := NewEngine(p).Decide(Request{Token: "demo-token-not-a-secret", Server: "sample",
		Kind: KindRequest, Method: "tools/call", Tool: "echo"})
	if !d.Allow {
		t.Errorf("example policy denies its own demo call: %s", d.Reason)
	}
}

// TestGoldenDecisions replays testdata/decisions/requests.json against
// testdata/decisions/policy.yaml and compares with decisions.golden.
// Run "go test ./internal/policy -update" after an intended change, then
// read the diff: every changed line is a changed security decision.
func TestGoldenDecisions(t *testing.T) {
	dir := filepath.Join("testdata", "decisions")
	policyData, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(policyData)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(p)

	var cases []struct {
		Name    string `json:"name"`
		Request struct {
			Token     string          `json:"token"`
			Server    string          `json:"server"`
			Kind      Kind            `json:"kind"`
			Method    string          `json:"method"`
			Tool      string          `json:"tool"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"request"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	var got strings.Builder
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Name] {
			t.Fatalf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
		r := c.Request
		d := engine.Decide(Request{Token: r.Token, Server: r.Server, Kind: r.Kind,
			Method: r.Method, Tool: r.Tool, Arguments: r.Arguments})

		if d.PolicyHash != p.Hash() {
			t.Errorf("%s: decision carries policy hash %q", c.Name, d.PolicyHash)
		}
		if d.Allow != (d.Code == CodeAllowed) {
			t.Errorf("%s: Allow=%v but Code=%s", c.Name, d.Allow, d.Code)
		}
		if !d.Allow && d.Reason == "" {
			t.Errorf("%s: denial without a reason", c.Name)
		}
		verdict := "DENY "
		if d.Allow {
			verdict = "ALLOW"
		}
		agent := d.Agent
		if agent == "" {
			agent = "-"
		}
		fmt.Fprintf(&got, "%s  %-22s agent=%-6s %s\n", verdict, d.Code, agent, c.Name)
	}

	goldenPath := filepath.Join(dir, "decisions.golden")
	if *update {
		if err := os.WriteFile(goldenPath, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got.String() != string(want) {
		t.Errorf("decisions differ from %s\n--- got ---\n%s--- want ---\n%s", goldenPath, got.String(), want)
	}
}

func TestRateLimit(t *testing.T) {
	p, err := Parse([]byte(minimal("tools:\n  search: {rate_limit: {per_minute: 3}}\n  other: {rate_limit: {per_minute: 1}}\n")))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(p)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	e.SetClock(func() time.Time { return now })

	call := func(tool string) Decision {
		return e.Decide(Request{Token: "test-token-alpha", Server: "files", Kind: KindRequest, Method: "tools/call", Tool: tool})
	}

	for i := 1; i <= 3; i++ {
		if d := call("search"); !d.Allow {
			t.Fatalf("call %d denied: %s", i, d.Reason)
		}
	}
	if d := call("search"); d.Allow || d.Code != CodeRateLimited {
		t.Fatalf("4th call in the same instant: got %s, want rate_limited", d.Code)
	}
	// Limits are per tool.
	if d := call("other"); !d.Allow {
		t.Errorf("another tool was affected: %s", d.Reason)
	}
	// One third of a minute refills exactly one call.
	now = now.Add(20 * time.Second)
	if d := call("search"); !d.Allow {
		t.Errorf("after 20s: %s", d.Reason)
	}
	if d := call("search"); d.Allow {
		t.Error("after 20s only one call should be allowed")
	}
	// A long idle period never banks more than the limit.
	now = now.Add(24 * time.Hour)
	allowed := 0
	for i := 0; i < 10; i++ {
		if call("search").Allow {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("after a day idle, %d calls allowed in a burst, want 3", allowed)
	}
	// A clock that jumps backwards must not grant extra calls.
	now = now.Add(-time.Hour)
	if d := call("search"); d.Allow {
		t.Error("clock going backwards granted a call")
	}
}

// TestArgumentRulesFailClosed pins the behaviour of the unimplemented
// matcher: a tool with an "arguments" section is denied, whatever is sent.
// Replace this test when the hand-written matcher lands.
func TestArgumentRulesFailClosed(t *testing.T) {
	p, err := Parse([]byte(minimal("tools:\n  write: {arguments: {path: {path_under: /workspace}}}\n")))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(p)
	for _, args := range []string{``, `{}`, `{"path":"/workspace/a.txt"}`, `{"path":"/etc/passwd"}`, `[]`, `{"path":`} {
		d := e.Decide(Request{Token: "test-token-alpha", Server: "files", Kind: KindRequest,
			Method: "tools/call", Tool: "write", Arguments: json.RawMessage(args)})
		if d.Allow || d.Code != CodeArgumentsRejected {
			t.Errorf("arguments %q: got %s, want arguments_rejected", args, d.Code)
		}
	}
}

// FuzzParse: the parser must never panic, and anything it accepts must be a
// policy the engine can evaluate with default deny intact.
func FuzzParse(f *testing.F) {
	for _, dir := range []string{filepath.Join("testdata", "decisions"), filepath.Join("..", "..", "examples")} {
		if data, err := os.ReadFile(filepath.Join(dir, "policy.yaml")); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte(minimal("tools:\n  t: {arguments: {p: {path_under: /w, pattern: \"^a+$\"}}}\n")))
	f.Add([]byte("version: 1\nagents: []\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("{\"version\":1,\"agents\":[]}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if p != nil {
				t.Fatal("Parse returned both a policy and an error")
			}
			return
		}
		if p.Version != 1 || len(p.Agents) == 0 || len(p.Hash()) != 64 {
			t.Fatalf("accepted policy breaks invariants: %+v", p)
		}
		e := NewEngine(p)
		for _, a := range p.Agents {
			if !nameRE.MatchString(a.Name) || !isSHA256Hex(a.TokenSHA256) {
				t.Fatalf("accepted agent breaks invariants: %+v", a)
			}
			for _, srv := range a.Servers {
				for _, tool := range srv.Tools {
					for _, c := range tool.Arguments {
						if (c.Pattern != nil) != (c.Regexp != nil) {
							t.Fatal("pattern and compiled regexp disagree")
						}
					}
				}
			}
		}
		// Default deny holds for any accepted policy: no token, no entry.
		for _, r := range []Request{
			{Server: "files", Kind: KindRequest, Method: "tools/call", Tool: "t"},
			{Token: "not-a-real-token", Server: "files", Kind: KindRequest, Method: "tools/list"},
			{Token: p.Agents[0].TokenSHA256, Server: "files", Kind: KindStream},
		} {
			if d := e.Decide(r); d.Allow {
				t.Fatalf("unauthenticated request allowed: %+v", r)
			}
		}
	})
}
