package policy

import (
	"encoding/json"
	"path"
	"strings"
	"testing"
)

// toolFrom parses a policy whose single tool "t" has the given YAML body,
// so tests exercise constraints exactly as Parse produces them.
func toolFrom(t testing.TB, body string) *Tool {
	t.Helper()
	p, err := Parse([]byte(minimal("tools:\n  t:\n" + indent(body, 4))))
	if err != nil {
		t.Fatalf("policy does not parse: %v\n%s", err, body)
	}
	tool := p.Agents[0].Servers["files"].Tools["t"]
	return &tool
}

func match(t testing.TB, tool *Tool, argsJSON string) error {
	t.Helper()
	args, err := decodeArguments(json.RawMessage(argsJSON))
	if err != nil {
		t.Fatalf("test arguments are not an object: %v", err)
	}
	return matchArguments(tool, args)
}

type argCase struct {
	args  string
	allow bool
}

func runCases(t *testing.T, body string, cases []argCase) {
	t.Helper()
	tool := toolFrom(t, body)
	for _, c := range cases {
		err := match(t, tool, c.args)
		if (err == nil) != c.allow {
			t.Errorf("policy:\n%s\nargs %s: allowed=%v (%v), want allowed=%v", body, c.args, err == nil, err, c.allow)
		}
		if err != nil && err.Error() == "" {
			t.Errorf("args %s: denial without an explanation", c.args)
		}
	}
}

func TestPathUnder(t *testing.T) {
	runCases(t, "arguments:\n  path: {path_under: /workspace}\n", []argCase{
		{`{"path":"/workspace"}`, true},
		{`{"path":"/workspace/a.txt"}`, true},
		{`{"path":"/workspace/deep/er/file name.md"}`, true},
		{`{"path":"/workspace/..hidden"}`, true}, // a name that merely starts with dots
		{`{"path":"/workspace/caf\u00e9.txt"}`, true},

		{`{"path":"/workspace-evil/a.txt"}`, false}, // the prefix trap
		{`{"path":"/workspaces"}`, false},
		{`{"path":"/etc/passwd"}`, false},
		{`{"path":"/"}`, false},
		{`{"path":"/workspace/../etc/passwd"}`, false},
		{`{"path":"/workspace/a/../b"}`, false}, // cleans to inside, still refused
		{`{"path":"/workspace/.."}`, false},
		{`{"path":"/workspace/./a"}`, false},
		{`{"path":"/workspace//a"}`, false},
		{`{"path":"//workspace/a"}`, false},
		{`{"path":"/workspace/"}`, false},
		{`{"path":"workspace/a.txt"}`, false},
		{`{"path":"./workspace/a"}`, false},
		{`{"path":"~/workspace/a"}`, false},
		{`{"path":""}`, false},
		{`{"path":"/workspace/a\u0000.txt"}`, false},
		{`{"path":"/workspace/a\nb"}`, false},
		{`{"path":"/workspace\\..\\etc"}`, false},
		{`{"path":"/WORKSPACE/a"}`, false},
		{`{"path":"file:///workspace/a"}`, false},
		{`{"path":" /workspace/a"}`, false},
		{`{"path":null}`, false},
		{`{"path":7}`, false},
		{`{"path":{"p":"/workspace/a"}}`, false},
		{`{"path":["/workspace/a","/workspace/b"]}`, true},
		{`{"path":["/workspace/a","/etc/passwd"]}`, false},
		{`{"path":["/workspace/a",["/workspace/b"]]}`, false},
		{`{"path":[]}`, true},
		{`{}`, false},
		{`{"Path":"/workspace/a"}`, false},
		{`{"path":"/workspace/a","mode":"w"}`, false},
	})

	runCases(t, "arguments:\n  path: {path_under: /}\n", []argCase{
		{`{"path":"/anything/at/all"}`, true},
		{`{"path":"/"}`, true},
		{`{"path":"/a/../b"}`, false},
		{`{"path":"relative"}`, false},
	})
}

func TestEmailDomain(t *testing.T) {
	runCases(t, "arguments:\n  to: {email_domain: example.com}\n", []argCase{
		{`{"to":"sam@example.com"}`, true},
		{`{"to":"sam.o'neil+tag@EXAMPLE.com"}`, true},
		{`{"to":["a@example.com","b@example.com"]}`, true},

		{`{"to":"sam@evil.com"}`, false},
		{`{"to":"sam@example.com.evil.com"}`, false},
		{`{"to":"sam@mail.example.com"}`, false}, // sub-domains are not the domain
		{`{"to":"sam@evilexample.com"}`, false},
		{`{"to":"sam@example.com@evil.com"}`, false},
		{`{"to":"sam@evil.com@example.com"}`, false},
		{`{"to":"\"sam@example.com\"@evil.com"}`, false},
		{`{"to":"Sam <sam@evil.com> sam@example.com"}`, false},
		{`{"to":"sam@example.com, eve@evil.com"}`, false},
		{`{"to":"sam@example.com;eve@evil.com"}`, false},
		{`{"to":"sam@example.com\nBcc: eve@evil.com"}`, false},
		{`{"to":"sam@example.com "}`, false},
		{`{"to":"sam@example.com."}`, false},
		{`{"to":"sam(comment)@example.com"}`, false},
		{`{"to":"sam@exampl\u0435.com"}`, false}, // Cyrillic look-alike letter
		{`{"to":"@example.com"}`, false},
		{`{"to":"sam@"}`, false},
		{`{"to":"example.com"}`, false},
		{`{"to":""}`, false},
		{`{"to":["a@example.com","b@evil.com"]}`, false},
		{`{"to":{"address":"a@example.com"}}`, false},
		{`{"to":null}`, false},
	})
}

func TestEqualsAndOneOf(t *testing.T) {
	runCases(t, "arguments:\n  n: {equals: 5}\n", []argCase{
		{`{"n":5}`, true}, {`{"n":5.0}`, true}, {`{"n":5e0}`, true}, {`{"n":0.5e1}`, true},
		{`{"n":"5"}`, false}, {`{"n":5.0000001}`, false}, {`{"n":6}`, false}, {`{"n":-5}`, false},
		{`{"n":true}`, false}, {`{"n":null}`, false}, {`{"n":[5]}`, false}, {`{"n":{"v":5}}`, false},
	})
	// Exact comparison: neighbours that a float64 cannot tell apart differ.
	runCases(t, "arguments:\n  n: {equals: 9007199254740992}\n", []argCase{
		{`{"n":9007199254740992}`, true}, {`{"n":9007199254740993}`, false},
	})
	runCases(t, "arguments:\n  s: {equals: \"5\"}\n", []argCase{
		{`{"s":"5"}`, true}, {`{"s":5}`, false}, {`{"s":"5 "}`, false}, {`{"s":"05"}`, false},
	})
	runCases(t, "arguments:\n  b: {equals: false}\n", []argCase{
		{`{"b":false}`, true}, {`{"b":true}`, false}, {`{"b":0}`, false}, {`{"b":"false"}`, false}, {`{"b":null}`, false},
	})
	runCases(t, "arguments:\n  mode: {one_of: [read, 2, true]}\n", []argCase{
		{`{"mode":"read"}`, true}, {`{"mode":2}`, true}, {`{"mode":true}`, true},
		{`{"mode":"write"}`, false}, {`{"mode":"READ"}`, false}, {`{"mode":"2"}`, false},
		{`{"mode":["read"]}`, false}, {`{"mode":false}`, false}, {`{}`, false},
	})
}

func TestPrefixPatternAndLength(t *testing.T) {
	runCases(t, "arguments:\n  url: {prefix: \"https://api.example.com/\"}\n", []argCase{
		{`{"url":"https://api.example.com/v1/items"}`, true},
		{`{"url":"https://api.example.com"}`, false},
		{`{"url":"https://api.example.com.evil.com/"}`, false},
		{`{"url":"http://api.example.com/"}`, false},
		{`{"url":" https://api.example.com/"}`, false},
		{`{"url":["https://api.example.com/a","https://evil.com/"]}`, false},
	})
	// A pattern must match the whole value, even without ^ and $, and even
	// when an earlier alternative matches only part of it.
	runCases(t, "arguments:\n  id: {pattern: \"[a-z]+|[a-z]+-[0-9]+\"}\n", []argCase{
		{`{"id":"abc"}`, true}, {`{"id":"abc-42"}`, true},
		{`{"id":"abc; rm -rf /"}`, false}, {`{"id":"ABC"}`, false}, {`{"id":"abc\n"}`, false},
		{`{"id":"abc\nabc"}`, false}, {`{"id":""}`, false}, {`{"id":42}`, false},
	})
	runCases(t, "arguments:\n  id: {pattern: \"(?m)^ok$\"}\n", []argCase{
		{`{"id":"ok"}`, true}, {`{"id":"ok\nrm -rf /"}`, false},
	})
	runCases(t, "arguments:\n  note: {max_length: 5}\n", []argCase{
		{`{"note":""}`, true}, {`{"note":"hello"}`, true}, {`{"note":"h\u00e9llo"}`, true}, // 5 characters, 6 bytes
		{`{"note":"hello!"}`, false}, {`{"note":["hi","toolong"]}`, false}, {`{"note":12345}`, false},
	})
	// Every condition must hold.
	runCases(t, "arguments:\n  path: {path_under: /workspace, pattern: \".*\\\\.md\", max_length: 20}\n", []argCase{
		{`{"path":"/workspace/a.md"}`, true},
		{`{"path":"/workspace/a.txt"}`, false},
		{`{"path":"/etc/a.md"}`, false},
		{`{"path":"/workspace/a-very-long-name.md"}`, false},
	})
}

func TestRequiredOptionalAndUnlisted(t *testing.T) {
	runCases(t, "arguments:\n  to: {email_domain: example.com}\n  cc: {email_domain: example.com, optional: true}\n", []argCase{
		{`{"to":"a@example.com"}`, true},
		{`{"to":"a@example.com","cc":"b@example.com"}`, true},
		{`{"to":"a@example.com","cc":"b@evil.com"}`, false}, // optional is not unchecked
		{`{"to":"a@example.com","cc":null}`, false},
		{`{"cc":"b@example.com"}`, false},
		{`{"to":"a@example.com","bcc":"eve@evil.com"}`, false},
		{`{"to":"a@example.com","":"x"}`, false},
	})
	runCases(t, "allow_other_arguments: true\narguments:\n  to: {email_domain: example.com}\n", []argCase{
		{`{"to":"a@example.com","subject":"hi","body":{"any":["thing"]}}`, true},
		{`{"to":"a@evil.com","subject":"hi"}`, false},
		{`{"subject":"hi"}`, false},
	})
	// An empty "arguments" section means the tool takes no arguments.
	runCases(t, "arguments: {}\n", []argCase{
		{`{}`, true}, {`{"anything":1}`, false},
	})
}

func TestMatcherDefensiveCases(t *testing.T) {
	if err := matchArguments(nil, map[string]any{}); err == nil {
		t.Error("nil tool allowed")
	}
	if err := matchArguments(&Tool{}, map[string]any{}); err == nil {
		t.Error("tool without argument rules allowed by the matcher")
	}
	// Constraints built by hand, bypassing Parse, must not become "allow".
	pattern := "ok"
	for name, c := range map[string]Constraint{
		"no conditions":      {},
		"uncompiled pattern": {Pattern: &pattern},
		"equals a list":      {Equals: []any{"a"}},
	} {
		tool := &Tool{Arguments: map[string]Constraint{"x": c}}
		if err := matchArguments(tool, map[string]any{"x": "ok"}); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	// Values of types the JSON decoder never produces are refused, not trusted.
	tool := toolFrom(t, "arguments:\n  n: {equals: 5}\n")
	for _, v := range []any{int(5), int64(5), float32(5), []byte("5"), struct{}{}} {
		if err := matchArguments(tool, map[string]any{"n": v}); err == nil {
			t.Errorf("value of type %T allowed", v)
		}
	}
	if err := matchArguments(tool, map[string]any{"n": float64(5)}); err != nil {
		t.Errorf("float64(5) refused: %v", err)
	}
}

// TestArgumentRulesThroughEngine: the engine reports argument violations
// with the right code, and refused calls do not use up the rate limit.
func TestArgumentRulesThroughEngine(t *testing.T) {
	p, err := Parse([]byte(minimal("tools:\n  write:\n    rate_limit: {per_minute: 1}\n    arguments:\n      path: {path_under: /workspace}\n")))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(p)
	call := func(args string) Decision {
		return e.Decide(Request{Token: "test-token-alpha", Server: "files", Kind: KindRequest,
			Method: "tools/call", Tool: "write", Arguments: json.RawMessage(args)})
	}
	for _, args := range []string{``, `{}`, `{"path":"/etc/passwd"}`, `[]`, `{"path":`, `{"path":"/workspace/a"} {"path":"/etc"}`} {
		if d := call(args); d.Allow || d.Code != CodeArgumentsRejected {
			t.Errorf("arguments %q: got %s, want arguments_rejected", args, d.Code)
		}
	}
	if d := call(`{"path":"/workspace/a.txt"}`); !d.Allow {
		t.Errorf("valid call refused after rejected ones: %s (%s)", d.Code, d.Reason)
	}
	if d := call(`{"path":"/workspace/a.txt"}`); d.Code != CodeRateLimited {
		t.Errorf("second valid call: got %s, want rate_limited", d.Code)
	}
}

// FuzzMatchArguments: the matcher must never panic, and whatever it allows
// must really satisfy the policy when checked independently.
func FuzzMatchArguments(f *testing.F) {
	for _, s := range []string{
		`{"path":"/workspace/a.txt","to":"a@example.com","mode":"read"}`,
		`{"path":"/workspace/../etc","to":"a@example.com@evil.com","mode":"x"}`,
		`{"path":["/workspace/a"],"to":["a@example.com"],"mode":"read","extra":1}`,
		`{"path":null}`, `{}`, `{"path":"/workspace/\u0000"}`, `{"to":"a@EXAMPLE.COM"}`,
	} {
		f.Add(s)
	}
	tool := toolFrom(f, "arguments:\n  path: {path_under: /workspace, optional: true}\n  to: {email_domain: example.com, optional: true}\n  mode: {one_of: [read, list], optional: true}\n")

	f.Fuzz(func(t *testing.T, raw string) {
		args, err := decodeArguments(json.RawMessage(raw))
		if err != nil {
			return
		}
		if matchArguments(tool, args) != nil {
			return
		}
		// Allowed. Check each claim the policy makes, the slow obvious way.
		for name, value := range args {
			values, _ := stringValues(value)
			switch name {
			case "path":
				for _, p := range values {
					if strings.Contains(p, "..") && strings.Contains("/"+p+"/", "/../") {
						t.Fatalf("allowed a path with a .. segment: %q", p)
					}
					if c := path.Clean(p); c != "/workspace" && !strings.HasPrefix(c, "/workspace/") {
						t.Fatalf("allowed a path outside /workspace: %q", p)
					}
				}
				if values == nil {
					t.Fatalf("allowed a non-string path: %#v", value)
				}
			case "to":
				for _, a := range values {
					if strings.Count(a, "@") != 1 || !strings.HasSuffix(strings.ToLower(a), "@example.com") || strings.ContainsAny(a, " ,;<>\"\n\r\t") {
						t.Fatalf("allowed an address that is not plainly at example.com: %q", a)
					}
				}
				if values == nil {
					t.Fatalf("allowed a non-string address: %#v", value)
				}
			case "mode":
				if value != "read" && value != "list" {
					t.Fatalf("allowed mode %#v", value)
				}
			default:
				t.Fatalf("allowed an unlisted argument %q", name)
			}
		}
	})
}
