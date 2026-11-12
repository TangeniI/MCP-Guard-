// Package policy loads MCP Guard policies and decides whether a call is
// allowed. The rule is default deny: an agent, server, method or tool that
// the policy does not name does not exist as far as the gateway is concerned.
//
// This package knows nothing about HTTP or the proxy.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"go.yaml.in/yaml/v3"
)

// MaxPolicyBytes caps the size of a policy file.
const MaxPolicyBytes = 1 << 20

//go:embed policy.schema.json
var schemaJSON []byte

var schema = mustResolveSchema()

func mustResolveSchema() *jsonschema.Resolved {
	var s jsonschema.Schema
	if err := json.Unmarshal(schemaJSON, &s); err != nil {
		panic("policy: embedded schema is invalid: " + err.Error())
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		panic("policy: embedded schema does not resolve: " + err.Error())
	}
	return rs
}

// Schema returns the JSON Schema that policies are validated against.
func Schema() []byte { return bytes.Clone(schemaJSON) }

// Policy is a validated policy document.
type Policy struct {
	Version int     `json:"version"`
	Agents  []Agent `json:"agents"`

	hash string
}

// Hash identifies the exact policy text, for the audit log.
func (p *Policy) Hash() string { return p.hash }

// Agent is one agent identity and what it may reach.
type Agent struct {
	Name        string            `json:"name"`
	TokenSHA256 string            `json:"token_sha256"`
	Servers     map[string]Server `json:"servers"`
}

// Server is what an agent may do on one MCP server.
type Server struct {
	Methods []string        `json:"methods"`
	Tools   map[string]Tool `json:"tools"`
}

// Tool is the rule for one tool.
type Tool struct {
	RequiresApproval    bool                  `json:"requires_approval"`
	RateLimit           *RateLimit            `json:"rate_limit"`
	Arguments           map[string]Constraint `json:"arguments"`
	AllowOtherArguments bool                  `json:"allow_other_arguments"`
}

// RateLimit bounds how often one agent may call one tool.
type RateLimit struct {
	PerMinute int `json:"per_minute"`
}

// Constraint restricts one argument. Every condition that is set must hold.
type Constraint struct {
	Equals      any     `json:"equals"`       // string, float64 or bool; nil if unset
	OneOf       []any   `json:"one_of"`       // strings, float64s or bools
	Prefix      *string `json:"prefix"`       // string starts with
	PathUnder   *string `json:"path_under"`   // path is inside this directory
	EmailDomain *string `json:"email_domain"` // address is at exactly this domain
	Pattern     *string `json:"pattern"`      // RE2 regular expression
	MaxLength   *int    `json:"max_length"`   // string length limit, in characters

	// Optional lets the argument be left out. If it is present, every
	// condition still applies. Without it, a listed argument is required.
	Optional bool `json:"optional"`

	// Regexp is Pattern compiled and anchored to match a whole value, set
	// by Parse when Pattern is set.
	Regexp *regexp.Regexp `json:"-"`
}

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Parse reads, validates and returns a policy. Any problem is an error: the
// gateway must refuse to start rather than run with a policy it only partly
// understood.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy: larger than %d bytes", MaxPolicyBytes)
	}

	// YAML -> generic value. yaml.v3 rejects duplicate mapping keys.
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("policy: invalid YAML: %w", err)
	}
	if doc == nil {
		return nil, errors.New("policy: document is empty")
	}

	// Normalise through JSON so the schema check and the typed decode both
	// see the same thing. This also rejects non-string keys and NaN.
	asJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("policy: not representable as JSON: %w", err)
	}
	var instance any
	if err := json.Unmarshal(asJSON, &instance); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return nil, fmt.Errorf("policy: does not match schema: %w", err)
	}

	var p Policy
	dec := json.NewDecoder(bytes.NewReader(asJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	sum := sha256.Sum256(data)
	p.hash = hex.EncodeToString(sum[:])
	return &p, nil
}

// validate performs the checks a JSON Schema cannot express. It repeats the
// structural ones that matter for safety, so the engine never depends on the
// schema alone.
func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported version %d", p.Version)
	}
	if len(p.Agents) == 0 {
		return errors.New("no agents defined")
	}
	names := make(map[string]struct{})
	tokens := make(map[string]string)
	for i := range p.Agents {
		a := &p.Agents[i]
		if !nameRE.MatchString(a.Name) {
			return fmt.Errorf("agent %d: invalid name %q", i, a.Name)
		}
		if _, dup := names[a.Name]; dup {
			return fmt.Errorf("agent %q is defined twice", a.Name)
		}
		names[a.Name] = struct{}{}

		if !isSHA256Hex(a.TokenSHA256) {
			return fmt.Errorf("agent %q: token_sha256 must be 64 lower-case hex characters", a.Name)
		}
		if other, dup := tokens[a.TokenSHA256]; dup {
			return fmt.Errorf("agents %q and %q share a token", other, a.Name)
		}
		tokens[a.TokenSHA256] = a.Name

		for _, serverName := range sortedKeys(a.Servers) {
			if !nameRE.MatchString(serverName) {
				return fmt.Errorf("agent %q: invalid server name %q", a.Name, serverName)
			}
			srv := a.Servers[serverName]
			for _, m := range srv.Methods {
				if m == "" {
					return fmt.Errorf("agent %q, server %q: empty method name", a.Name, serverName)
				}
				if m == "tools/call" {
					return fmt.Errorf("agent %q, server %q: tools/call cannot be allowed as a method; list tools under \"tools\"", a.Name, serverName)
				}
			}
			for _, toolName := range sortedKeys(srv.Tools) {
				if toolName == "" {
					return fmt.Errorf("agent %q, server %q: empty tool name", a.Name, serverName)
				}
				tool := srv.Tools[toolName]
				where := fmt.Sprintf("agent %q, server %q, tool %q", a.Name, serverName, toolName)
				if err := validateTool(&tool); err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
				srv.Tools[toolName] = tool // keep compiled patterns
			}
		}
	}
	return nil
}

func validateTool(t *Tool) error {
	if t.RateLimit != nil && t.RateLimit.PerMinute < 1 {
		return errors.New("rate_limit.per_minute must be at least 1")
	}
	if t.AllowOtherArguments && t.Arguments == nil {
		return errors.New("allow_other_arguments needs an \"arguments\" section")
	}
	for _, argName := range sortedKeys(t.Arguments) {
		if argName == "" {
			return errors.New("empty argument name")
		}
		c := t.Arguments[argName]
		if err := validateConstraint(&c); err != nil {
			return fmt.Errorf("argument %q: %w", argName, err)
		}
		t.Arguments[argName] = c
	}
	return nil
}

func validateConstraint(c *Constraint) error {
	set := 0
	if c.Equals != nil {
		set++
		if !isScalar(c.Equals) {
			return errors.New("equals must be a string, number or boolean")
		}
	}
	if c.OneOf != nil {
		set++
		if len(c.OneOf) == 0 {
			return errors.New("one_of must not be empty")
		}
		for _, v := range c.OneOf {
			if !isScalar(v) {
				return errors.New("one_of values must be strings, numbers or booleans")
			}
		}
	}
	if c.Prefix != nil {
		set++
		if *c.Prefix == "" {
			return errors.New("prefix must not be empty")
		}
	}
	if c.PathUnder != nil {
		set++
		if p := *c.PathUnder; !strings.HasPrefix(p, "/") || path.Clean(p) != p {
			return fmt.Errorf("path_under %q must be a clean absolute path (no \"..\", \".\" or trailing slash)", p)
		}
	}
	if c.EmailDomain != nil {
		set++
		d := *c.EmailDomain
		if d == "" || strings.ContainsAny(d, "@ /") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
			return fmt.Errorf("email_domain %q must be a bare domain such as example.com", d)
		}
	}
	if c.Pattern != nil {
		set++
		if _, err := regexp.Compile(*c.Pattern); err != nil {
			return fmt.Errorf("pattern: %w", err)
		}
		// Anchor the whole pattern so it must match the entire value:
		// an unanchored "safe" would otherwise accept "unsafe; rm -rf /".
		re, err := regexp.Compile(`\A(?:` + *c.Pattern + `)\z`)
		if err != nil {
			return fmt.Errorf("pattern: %w", err)
		}
		c.Regexp = re
	}
	if c.MaxLength != nil {
		set++
		if *c.MaxLength < 0 {
			return errors.New("max_length must not be negative")
		}
	}
	if set == 0 {
		return errors.New("constraint has no conditions")
	}
	return nil
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, float64, bool:
		return true
	}
	return false
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
