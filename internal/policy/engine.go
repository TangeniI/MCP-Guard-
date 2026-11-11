package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// Kind is the kind of thing an agent is trying to do.
type Kind string

const (
	KindRequest      Kind = "request"      // JSON-RPC request
	KindNotification Kind = "notification" // JSON-RPC notification
	KindResponse     Kind = "response"     // JSON-RPC response to a server request
	KindStream       Kind = "stream"       // HTTP GET/DELETE on the endpoint (older revisions)
)

// Request is one thing to decide on.
type Request struct {
	Token     string          // the agent's bearer token, as presented
	Server    string          // gateway server name
	Kind      Kind            //
	Method    string          // JSON-RPC method; empty for responses and streams
	Tool      string          // tool name, for tools/call
	Arguments json.RawMessage // params.arguments, for tools/call; may be empty
}

// Code says why a decision was made. Codes are stable; they appear in the
// audit log, metrics and eval results.
type Code string

const (
	CodeAllowed             Code = "allowed"
	CodeUnauthenticated     Code = "unauthenticated"
	CodeServerNotAllowed    Code = "server_not_allowed"
	CodeMethodNotAllowed    Code = "method_not_allowed"
	CodeToolNotAllowed      Code = "tool_not_allowed"
	CodeApprovalUnavailable Code = "approval_unavailable"
	CodeArgumentsRejected   Code = "arguments_rejected"
	CodeRateLimited         Code = "rate_limited"
)

// Decision is the engine's answer.
type Decision struct {
	Allow      bool
	Code       Code
	Reason     string // human-readable; safe to show to the agent
	Agent      string // empty if the caller was not identified
	PolicyHash string
}

// baseMethods are the requests any agent may send to a server it is allowed
// to reach: protocol set-up and discovery. They invoke nothing.
var baseMethods = map[string]struct{}{
	"initialize":      {},
	"ping":            {},
	"server/discover": {},
	"tools/list":      {},
}

// Engine evaluates requests against one policy. It is safe for concurrent use.
type Engine struct {
	policy  *Policy
	byToken map[string]*Agent
	now     func() time.Time

	mu      sync.Mutex
	buckets map[bucketKey]*bucket
}

type bucketKey struct{ agent, server, tool string }

type bucket struct {
	tokens float64
	last   time.Time
}

// NewEngine builds an engine for a policy returned by Parse.
func NewEngine(p *Policy) *Engine {
	e := &Engine{
		policy:  p,
		byToken: make(map[string]*Agent, len(p.Agents)),
		now:     time.Now,
		buckets: make(map[bucketKey]*bucket),
	}
	for i := range p.Agents {
		e.byToken[p.Agents[i].TokenSHA256] = &p.Agents[i]
	}
	return e
}

// SetClock replaces the time source. For tests.
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// Decide answers one request. Every path that is not an explicit allow is a
// deny.
func (e *Engine) Decide(r Request) Decision {
	d := Decision{PolicyHash: e.policy.hash}
	deny := func(code Code, reason string) Decision {
		d.Allow, d.Code, d.Reason = false, code, reason
		return d
	}

	// 1. Who is calling?
	if r.Token == "" {
		return deny(CodeUnauthenticated, "no bearer token presented")
	}
	sum := sha256.Sum256([]byte(r.Token))
	agent, ok := e.byToken[hex.EncodeToString(sum[:])]
	if !ok {
		return deny(CodeUnauthenticated, "bearer token not recognised")
	}
	d.Agent = agent.Name

	// 2. May this agent reach this server at all?
	server, ok := agent.Servers[r.Server]
	if !ok {
		return deny(CodeServerNotAllowed, "server is not allowed for this agent")
	}

	// 3. What is it trying to do?
	switch r.Kind {
	case KindStream, KindResponse:
		// Transport plumbing and answers to the server's own requests.
		// Neither can invoke a tool.
		return e.allow(d)

	case KindNotification:
		if strings.HasPrefix(r.Method, "notifications/") {
			return e.allow(d)
		}
		return deny(CodeMethodNotAllowed, "notification "+quote(r.Method)+" is not allowed")

	case KindRequest:
		// handled below

	default:
		return deny(CodeMethodNotAllowed, "unknown message kind")
	}

	if r.Method != "tools/call" {
		if _, ok := baseMethods[r.Method]; ok {
			return e.allow(d)
		}
		for _, m := range server.Methods {
			if m == r.Method {
				return e.allow(d)
			}
		}
		return deny(CodeMethodNotAllowed, "method "+quote(r.Method)+" is not allowed for this agent")
	}

	// 4. Tool calls.
	tool, ok := server.Tools[r.Tool]
	if !ok || r.Tool == "" {
		return deny(CodeToolNotAllowed, "tool "+quote(r.Tool)+" is not allowed for this agent")
	}
	if tool.RequiresApproval {
		// The approval flow arrives in milestone 3. Until a human can
		// say yes, the answer is no.
		return deny(CodeApprovalUnavailable, "tool "+quote(r.Tool)+" requires human approval, which is not available")
	}
	if tool.Arguments != nil {
		args, err := decodeArguments(r.Arguments)
		if err != nil {
			return deny(CodeArgumentsRejected, "arguments could not be read: "+err.Error())
		}
		if err := matchArguments(&tool, args); err != nil {
			return deny(CodeArgumentsRejected, "arguments rejected: "+err.Error())
		}
	}

	// 5. Rate limit last, so refused calls do not use up the allowance.
	if tool.RateLimit != nil && !e.take(bucketKey{agent.Name, r.Server, r.Tool}, tool.RateLimit.PerMinute) {
		return deny(CodeRateLimited, "rate limit reached for tool "+quote(r.Tool))
	}
	return e.allow(d)
}

func (e *Engine) allow(d Decision) Decision {
	d.Allow, d.Code, d.Reason = true, CodeAllowed, ""
	return d
}

// take removes one token from a bucket that holds at most perMinute tokens
// and refills continuously at perMinute per minute.
func (e *Engine) take(key bucketKey, perMinute int) bool {
	now := e.now()
	capacity := float64(perMinute)

	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		e.buckets[key] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(capacity, b.tokens+elapsed.Minutes()*capacity)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// decodeArguments turns params.arguments into a map. Numbers stay as
// json.Number so large integers are not silently rounded.
func decodeArguments(raw json.RawMessage) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after arguments")
	}
	args, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("arguments must be an object")
	}
	return args, nil
}

// quote renders an untrusted name for a reason string, bounded in length.
func quote(s string) string {
	const limit = 80
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	b, _ := json.Marshal(s)
	return string(b)
}
