// Package proxy is the MCP Guard data path: a Streamable HTTP reverse proxy
// that sits between an agent and its MCP servers.
//
// It works at the HTTP level rather than re-implementing an MCP server, so it
// stays invisible to both sides and does not depend on a protocol revision:
// headers, sessions and SSE streams pass through untouched. What it adds is a
// strict parse of every client-to-server JSON-RPC message, which is the point
// where later milestones attach policy, approval and audit.
//
// Architecture rule: this package must not import the policy store. Decisions
// reach it through interfaces defined here.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultMaxBodyBytes caps a client request body (4 MiB, the Go SDK's default).
const DefaultMaxBodyBytes = 4 << 20

// AuthRequest is what the proxy asks an Authorizer about.
type AuthRequest struct {
	Server      string  // gateway server name from the URL
	BearerToken string  // from the Authorization header; empty if absent
	HTTPMethod  string  // POST, GET or DELETE
	Message     Message // zero for GET and DELETE
}

// Decision is an Authorizer's answer. The zero value is a denial.
type Decision struct {
	Allow           bool
	Unauthenticated bool   // denied because the caller could not be identified
	NeedsApproval   bool   // denied only for want of a human's approval
	Agent           string // who the caller is, if known
	Code            string // stable machine-readable reason
	Reason          string // human-readable reason; shown to the agent
	PolicyVersion   string // which policy produced this decision
}

// Authorizer decides whether an exchange may proceed. The proxy depends on
// this interface only; it never imports the policy package.
type Authorizer interface {
	Authorize(AuthRequest) Decision
}

// AllowAll is an Authorizer that permits everything. It exists for the
// "guard off" baseline in evaluations and must be chosen explicitly.
type AllowAll struct{}

// Authorize implements Authorizer.
func (AllowAll) Authorize(AuthRequest) Decision {
	return Decision{Allow: true, Code: "allowed", PolicyVersion: "allow-all"}
}

// ApprovalRequest is a tool call the policy allows only with a human's consent.
type ApprovalRequest struct {
	Agent   string
	Server  string
	Message Message
}

// ApprovalOutcome is the result of asking. The zero value is a refusal.
type ApprovalOutcome struct {
	Approved bool
	Code     string        // stable machine-readable outcome
	Reason   string        // human-readable; shown to the agent when refused
	ID       string        // approval request ID, for the audit log
	By       string        // who decided, if a human did
	Wait     time.Duration // how long the call was held
}

// Approver obtains a human decision. It blocks until there is one, and must
// return a refusal when ctx is cancelled or its own time limit passes.
type Approver interface {
	RequestApproval(ctx context.Context, req ApprovalRequest) ApprovalOutcome
}

// Recorder stores the audit record of an exchange.
type Recorder interface {
	Record(Event) error
}

// Event describes one proxied exchange, emitted when the response is complete.
type Event struct {
	Time          time.Time // when the request arrived
	Server        string
	Agent         string
	HTTPMethod    string
	Message       Message
	Status        int           // HTTP status sent to the client
	Denied        bool          // true if the gateway refused it without calling upstream
	Code          string        // decision code, or "invalid" for malformed requests
	Reason        string        // why, when Denied
	PolicyVersion string        //
	Duration      time.Duration // total time in the gateway, including upstream

	Scanned      bool          // the tool result was examined (or could not be)
	Quarantined  bool          // the result was withheld from the model
	ScanVerdict  string        // "clean", "injection", "unsure", ...
	ScanSource   string        // which layer decided
	ScanRule     string        // rule id, if a rule matched
	ScanDetail   string        // match excerpt or judge's reason
	ScanDuration time.Duration // time spent scanning
	ResultBytes  int           // size of the tool result that was scanned
	ResultSHA256 string        // its hash, to match against the server's own logs
	ToolsListed  int           // tools/list: tools shown to the agent
	ToolsHidden  []string      // tools/list: "name: reason" for each tool withheld

	ApprovalID       string        // set when a human was asked
	ApprovedBy       string        // who answered, if anyone did
	ApprovalWait     time.Duration // time spent waiting for that answer
	UpstreamDuration time.Duration // time spent in the MCP server; zero if never called
}

// Config configures a Handler.
type Config struct {
	// Upstreams maps a server name to its MCP endpoint URL. The agent
	// reaches a server at /{name}/mcp. Names not listed here do not exist.
	Upstreams map[string]*url.URL

	// Authorizer decides every exchange. Required: there is no implicit
	// allow. Use AllowAll{} to run without a policy on purpose.
	Authorizer Authorizer

	// Approver handles tool calls that need a human. Nil means there is
	// nobody to ask, so those calls are refused.
	Approver Approver

	// Scanner examines tool results before the model sees them. Nil
	// disables scanning, which must be a deliberate choice by the caller.
	Scanner Scanner

	// PinTools remembers the first definition seen for each tool and blocks
	// a tool whose definition later changes.
	PinTools bool

	// Audit, if set, stores a record of every exchange. If a record cannot
	// be stored the gateway stops serving until one can: no audit, no calls.
	Audit Recorder

	// MaxBodyBytes caps client request bodies. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// AllowedOrigins lists extra Origin header values to accept. Requests
	// without an Origin header (non-browser clients) and loopback origins
	// are always accepted; anything else is refused, as the MCP spec requires.
	AllowedOrigins []string

	// Transport is used for upstream calls. Nil means http.DefaultTransport.
	Transport http.RoundTripper

	// Transports overrides Transport for individual servers, by name. It
	// is how non-HTTP upstreams (stdio servers) are plugged in; the URL in
	// Upstreams is then only a placeholder.
	Transports map[string]http.RoundTripper

	// Logger receives one line per exchange. Nil means slog.Default().
	Logger *slog.Logger

	// OnEvent, if set, is called once per exchange after it completes.
	OnEvent func(Event)
}

// Handler is the gateway's http.Handler.
type Handler struct {
	cfg       Config
	mux       *http.ServeMux
	auditDown atomic.Bool // the last audit record could not be stored
	tools     *toolRegistry
	upstreams map[string]*httputil.ReverseProxy
	origins   map[string]struct{}
}

type ctxKey struct{}

// New validates cfg and builds a Handler. A configuration the gateway cannot
// fully understand is an error: it must not start half-configured.
func New(cfg Config) (*Handler, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("proxy: no upstream servers configured")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("proxy: no authorizer configured")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	h := &Handler{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		upstreams: make(map[string]*httputil.ReverseProxy, len(cfg.Upstreams)),
		origins:   make(map[string]struct{}, len(cfg.AllowedOrigins)),
		tools:     newToolRegistry(),
	}
	for _, o := range cfg.AllowedOrigins {
		h.origins[o] = struct{}{}
	}
	for name, target := range cfg.Upstreams {
		if !validServerName(name) {
			return nil, fmt.Errorf("proxy: invalid server name %q (use letters, digits, '-' and '_')", name)
		}
		if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
			return nil, fmt.Errorf("proxy: upstream %q needs an absolute http(s) URL", name)
		}
		h.upstreams[name] = h.newReverseProxy(name, target)
	}

	h.mux.HandleFunc("/{server}/mcp", h.serveMCP)
	h.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if h.auditDown.Load() {
			http.Error(w, "audit log unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func validServerName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func (h *Handler) newReverseProxy(name string, target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// One MCP endpoint per upstream: always the configured URL.
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = target.Path
			pr.Out.URL.RawPath = target.RawPath
			pr.Out.URL.RawQuery = target.RawQuery
			pr.Out.Host = target.Host
			// The bearer token identifies the agent to the gateway.
			// It is not the upstream's credential and must not leak.
			pr.Out.Header.Del("Authorization")
			// Let Go's transport negotiate (and undo) compression itself,
			// so the response hook always sees plain bytes.
			pr.Out.Header.Del("Accept-Encoding")
		},
		Transport:      h.transportFor(name),
		FlushInterval:  -1, // SSE: forward every event as it arrives
		ModifyResponse: h.scanResponse,
		ErrorLog:       slog.NewLogLogger(h.cfg.Logger.Handler(), slog.LevelWarn),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(r.Context().Err(), context.Canceled) {
				return // the client went away; nobody to answer
			}
			h.cfg.Logger.Warn("upstream error", "server", name, "err", err)
			var id json.RawMessage
			if st, ok := r.Context().Value(ctxKey{}).(*exchange); ok {
				id = st.msg.ID
			}
			writeRPCError(w, http.StatusBadGateway, id,
				&rpcError{codeUpstreamError, "MCP Guard: upstream server unavailable"})
		},
	}
}

func (h *Handler) serveMCP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	name := r.PathValue("server")
	rec := &statusRecorder{ResponseWriter: w}
	ev := Event{Time: start, Server: name, HTTPMethod: r.Method}
	st := &exchange{server: name}

	defer func() {
		ev.Status = rec.status()
		ev.Duration = time.Since(start)
		h.cfg.Logger.Info("mcp exchange",
			"server", ev.Server,
			"http_method", r.Method,
			"kind", string(ev.Message.Kind),
			"rpc_method", ev.Message.Method,
			"tool", ev.Message.Tool,
			"agent", ev.Agent,
			"status", ev.Status,
			"denied", ev.Denied,
			"code", ev.Code,
			"reason", ev.Reason,
			"policy_version", ev.PolicyVersion,
			"scan", ev.ScanVerdict,
			"quarantined", ev.Quarantined,
			"duration_ms", ev.Duration.Milliseconds(),
		)
		if h.cfg.Audit != nil {
			if err := h.cfg.Audit.Record(ev); err != nil {
				h.auditDown.Store(true)
				h.cfg.Logger.Error("audit record not stored; refusing further calls until the log recovers", "err", err)
			} else {
				h.auditDown.Store(false)
			}
		}
		if h.cfg.OnEvent != nil {
			h.cfg.OnEvent(ev)
		}
	}()

	deny := func(status int, e *rpcError) {
		ev.Denied, ev.Reason = true, e.Message
		if ev.Code == "" {
			ev.Code = "invalid"
		}
		writeRPCError(rec, status, ev.Message.ID, e)
	}

	// authorize asks the Authorizer and, on a denial, answers the client.
	authorize := func(msg Message) bool {
		d := h.cfg.Authorizer.Authorize(AuthRequest{
			Server:      name,
			BearerToken: bearerToken(r),
			HTTPMethod:  r.Method,
			Message:     msg,
		})
		ev.Agent, ev.Code, ev.PolicyVersion = d.Agent, d.Code, d.PolicyVersion
		st.agent, st.msg = d.Agent, msg
		if d.Allow {
			return true
		}
		if ev.Code == "" {
			ev.Code = "denied"
		}
		reason := d.Reason
		if reason == "" {
			reason = "not allowed"
		}
		if d.NeedsApproval && msg.Kind == KindRequest && msg.Method == "tools/call" {
			if h.cfg.Approver == nil {
				ev.Code = "approval_unavailable"
				reason += ", and no approver is configured"
			} else {
				out := h.cfg.Approver.RequestApproval(r.Context(), ApprovalRequest{Agent: d.Agent, Server: name, Message: msg})
				ev.ApprovalID, ev.ApprovedBy, ev.ApprovalWait = out.ID, out.By, out.Wait
				if out.Approved {
					ev.Code = "approved"
					return true
				}
				ev.Code = out.Code
				if ev.Code == "" || ev.Code == "approved" {
					ev.Code = "approval_denied"
				}
				if out.Reason != "" {
					reason = out.Reason
				}
			}
		}
		switch {
		case d.Unauthenticated:
			rec.Header().Set("WWW-Authenticate", `Bearer realm="mcp-guard"`)
			deny(http.StatusUnauthorized, &rpcError{codePolicyDenied, "MCP Guard: " + reason})
		case msg.Kind == KindRequest && msg.Method == "tools/call":
			// A refused tool call is answered as a failed tool result,
			// not a transport error: the model sees why and can carry
			// on with the rest of its task.
			ev.Denied, ev.Reason = true, reason
			writeToolDenied(rec, msg.ID, "Denied by MCP Guard policy: "+reason)
		default:
			deny(http.StatusForbidden, &rpcError{codePolicyDenied, "MCP Guard: " + reason})
		}
		return false
	}

	if h.auditDown.Load() {
		ev.Code = "audit_unavailable"
		deny(http.StatusServiceUnavailable, &rpcError{codeUpstreamError, "MCP Guard: audit log unavailable; calls are refused until it recovers"})
		return
	}

	upstream, ok := h.upstreams[name]
	if !ok {
		deny(http.StatusNotFound, &rpcError{codeInvalidRequest, "MCP Guard: unknown server"})
		return
	}
	if !h.originAllowed(r) {
		deny(http.StatusForbidden, &rpcError{codeInvalidRequest, "MCP Guard: origin not allowed"})
		return
	}

	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(http.MaxBytesReader(rec, r.Body, h.cfg.MaxBodyBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				deny(http.StatusRequestEntityTooLarge, &rpcError{codeInvalidRequest, "MCP Guard: request body too large"})
			} else {
				deny(http.StatusBadRequest, &rpcError{codeInvalidRequest, "MCP Guard: could not read request body"})
			}
			return
		}
		msg, rpcErr := inspect(body)
		ev.Message = msg
		if rpcErr == nil {
			rpcErr = checkHeaders(r.Header.Get, msg)
		}
		if rpcErr != nil {
			deny(http.StatusBadRequest, rpcErr)
			return
		}
		if !authorize(msg) {
			return
		}
		if msg.Kind == KindRequest && msg.Method == "tools/call" {
			if reason, detail := h.tools.blocked(name, msg.Tool); reason != "" {
				ev.Denied, ev.Code, ev.Reason = true, reason, detail
				text := "this tool's description was flagged as unsafe"
				if reason == toolChanged {
					text = "this tool's definition changed after it was first seen"
				}
				writeToolDenied(rec, msg.ID, "Denied by MCP Guard: "+text)
				return
			}
		}
		// Forward exactly the bytes that were inspected.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))

	case http.MethodGet, http.MethodDelete:
		// Pre-2026-07-28 revisions: GET opens the server-to-client SSE
		// stream and DELETE ends a session. Neither carries a client
		// message, so there is nothing to inspect. Newer servers answer 405.
		if !authorize(Message{}) {
			return
		}

	default:
		rec.Header().Set("Allow", "POST, GET, DELETE")
		deny(http.StatusMethodNotAllowed, &rpcError{codeInvalidRequest, "MCP Guard: method not allowed"})
		return
	}

	// What happened upstream is copied into the event in a defer, not after
	// the call: the reverse proxy aborts the handler (by panicking with
	// http.ErrAbortHandler) when the client hangs up while the response is
	// still being copied, and that exchange must still be recorded in full.
	// This defer runs before the one above that writes the audit record.
	upstreamStart := time.Now()
	defer func() {
		ev.UpstreamDuration = time.Since(upstreamStart) - st.scan.Duration
		ev.Scanned, ev.Quarantined = st.scanned, st.quarantined
		ev.ScanVerdict, ev.ScanSource, ev.ScanRule, ev.ScanDetail = st.scan.Verdict, st.scan.Source, st.scan.Rule, st.scan.Detail
		ev.ScanDuration, ev.ResultBytes, ev.ResultSHA256 = st.scan.Duration, st.resultBytes, st.resultHash
		ev.ToolsListed, ev.ToolsHidden = st.toolsListed, st.toolsHidden
	}()
	upstream.ServeHTTP(rec, r)
}

// originAllowed implements the Origin check the MCP spec requires of servers
// (DNS-rebinding protection). No Origin header means a non-browser client.
func (h *Handler) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if _, ok := h.origins[origin]; ok {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bearerToken returns the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// writeToolDenied answers a tools/call with a tool result marked as an error.
func writeToolDenied(w http.ResponseWriter, id json.RawMessage, text string) {
	type content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type result struct {
		Content []content `json:"content"`
		IsError bool      `json:"isError"`
	}
	body, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  result          `json:"result"`
	}{"2.0", id, result{[]content{{"text", text}}, true}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, e *rpcError) {
	if !json.Valid(id) {
		id = json.RawMessage("null")
	}
	body, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *rpcError       `json:"error"`
	}{"2.0", id, e})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// statusRecorder remembers the status code. Unwrap lets
// http.ResponseController reach the real writer for flushing SSE.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

func (h *Handler) transportFor(server string) http.RoundTripper {
	if t, ok := h.cfg.Transports[server]; ok && t != nil {
		return t
	}
	return h.cfg.Transport
}
