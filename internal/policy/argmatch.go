package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// The argument-constraint matcher: do this tool call's arguments satisfy
// the policy?
//
// NOTE ON AUTHORSHIP: the project brief (CLAUDE.md) set this file aside to be
// written by hand. At the project owner's request it was instead written
// with AI assistance. It is small and security-critical; read it and its
// tests critically before relying on it.
//
// The rules, in one place:
//
//   - Every argument named in the policy must be present, unless its
//     constraint says "optional: true". JSON null counts as a value, and it
//     fails every condition.
//   - Arguments the policy does not name are refused unless the tool sets
//     "allow_other_arguments: true".
//   - Every condition on a constraint must hold.
//   - equals and one_of compare one scalar with another, with no type
//     coercion: the string "5" is not the number 5.
//   - prefix, path_under, email_domain, pattern and max_length apply to a
//     string, or to a list of strings (each element must pass; an empty list
//     passes). Anything else fails.
//   - The answer is "no" whenever the matcher is not sure.
//
// What it cannot see: it compares text. It does not know that two paths are
// the same file through a symlink, that a server will URL-decode "%2e%2e",
// or that a domain it has not been told about is the same company.

// matchArguments returns nil if args satisfy tool's argument rules, and an
// error that explains the first violation otherwise. The engine only calls
// it for tools that have an "arguments" section.
func matchArguments(tool *Tool, args map[string]any) error {
	if tool == nil || tool.Arguments == nil {
		return errors.New("no argument rules to check against")
	}

	// Sorted, so the same call always reports the same violation.
	for _, name := range sortedKeys(tool.Arguments) {
		constraint := tool.Arguments[name]
		value, present := args[name]
		if !present {
			if constraint.Optional {
				continue
			}
			return fmt.Errorf("required argument %q is missing", name)
		}
		if err := matchConstraint(&constraint, value); err != nil {
			return fmt.Errorf("argument %q %w", name, err)
		}
	}

	if !tool.AllowOtherArguments {
		var extra []string
		for name := range args {
			if _, listed := tool.Arguments[name]; !listed {
				extra = append(extra, name)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			return fmt.Errorf("argument %s is not allowed by the policy", quote(extra[0]))
		}
	}
	return nil
}

// matchConstraint checks one value against every condition that is set.
func matchConstraint(c *Constraint, value any) error {
	set := false

	if c.Equals != nil {
		set = true
		if !scalarEqual(c.Equals, value) {
			return errors.New("does not equal the required value")
		}
	}
	if c.OneOf != nil {
		set = true
		allowed := false
		for _, want := range c.OneOf {
			if scalarEqual(want, value) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("is not one of the allowed values")
		}
	}

	if c.Prefix != nil || c.PathUnder != nil || c.EmailDomain != nil || c.Pattern != nil || c.MaxLength != nil {
		set = true
		values, ok := stringValues(value)
		if !ok {
			return errors.New("must be a string or a list of strings")
		}
		for _, s := range values {
			if err := matchString(c, s); err != nil {
				return err
			}
		}
	}

	if !set {
		// Parse rejects constraints with no conditions; if one gets here
		// anyway, it must not act as "anything goes".
		return errors.New("has a constraint with no conditions")
	}
	return nil
}

// matchString applies the string conditions to one string.
func matchString(c *Constraint, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("is not valid UTF-8")
	}
	if c.MaxLength != nil && utf8.RuneCountInString(s) > *c.MaxLength {
		return fmt.Errorf("is longer than %d characters", *c.MaxLength)
	}
	if c.Prefix != nil && !strings.HasPrefix(s, *c.Prefix) {
		return errors.New("does not start with the required prefix")
	}
	if c.PathUnder != nil {
		if err := pathUnder(*c.PathUnder, s); err != nil {
			return err
		}
	}
	if c.EmailDomain != nil {
		if err := emailAtDomain(*c.EmailDomain, s); err != nil {
			return err
		}
	}
	if c.Pattern != nil {
		// Regexp is anchored at parse time to match the whole value. A
		// constraint built without Parse has none, and fails.
		if c.Regexp == nil || !c.Regexp.MatchString(s) {
			return errors.New("does not match the required pattern")
		}
	}
	return nil
}

// stringValues accepts a string or a list of strings.
func stringValues(value any) ([]string, bool) {
	switch v := value.(type) {
	case string:
		return []string{v}, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// scalarEqual compares a policy value (string, float64 or bool) with an
// argument value (string, json.Number or bool; float64 if decoded without
// UseNumber). Types must agree. Numbers are compared exactly, as rationals,
// so 9007199254740993 does not equal 9007199254740992.
func scalarEqual(want, got any) bool {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case float64:
		wr, ok := new(big.Rat).SetString(big.NewFloat(w).Text('g', -1))
		if !ok {
			return false
		}
		gr, ok := numberAsRat(got)
		return ok && wr.Cmp(gr) == 0
	}
	return false
}

func numberAsRat(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case json.Number:
		return new(big.Rat).SetString(n.String())
	case float64:
		return new(big.Rat).SetString(big.NewFloat(n).Text('g', -1))
	}
	return nil, false
}

// pathUnder checks that p names something inside dir (or dir itself).
//
// It is deliberately strict. The path must be absolute and already in its
// simplest form: no ".." or "." segments, no doubled or trailing slashes.
// A path such as /workspace/a/../b is refused even though it cleans to
// something inside /workspace, because what ".." means on the server
// depends on symlinks the gateway cannot see.
func pathUnder(dir, p string) error {
	if p == "" || p[0] != '/' {
		return errors.New("must be an absolute path")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return errors.New("contains characters that are not allowed in a path")
		}
	}
	if path.Clean(p) != p {
		return errors.New("must be a plain path with no \"..\", \".\", doubled or trailing slashes")
	}
	// dir is validated at parse time to be clean and absolute.
	if dir == "/" || p == dir || strings.HasPrefix(p, dir+"/") {
		return nil
	}
	return errors.New("is outside the allowed directory")
}

// emailAtDomain checks that s is one plain address at exactly domain.
//
// Only the simple form local@domain is accepted. Display names, angle
// brackets, quotes, comments, lists of addresses in one string, and
// sub-domains of the allowed domain are all refused: each is a way to make
// a mail system deliver somewhere other than where the text appears to say.
func emailAtDomain(domain, s string) error {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || strings.Count(s, "@") != 1 {
		return errors.New("must be a single email address")
	}
	local, host := s[:at], s[at+1:]
	for _, r := range local {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune(`"(),:;<>[\]`, r) {
			return errors.New("must be a plain email address")
		}
	}
	for _, r := range host {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !isLetter && !(r >= '0' && r <= '9') && r != '-' && r != '.' {
			return errors.New("must be a plain email address")
		}
	}
	if !strings.EqualFold(host, domain) {
		return errors.New("is not at the allowed email domain")
	}
	return nil
}
