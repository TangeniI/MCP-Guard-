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
	"time"
)

// DefaultMaxBodyBytes caps a client request body (4 MiB, the Go SDK's default).
const DefaultMaxBodyBytes = 4 << 20

// Event describes one proxied exchange, emitted when the response is complete.
type Event struct {
	Server   string
	Message  Message
	Status   int           // HTTP status sent to the client
	Denied   bool          // true if the gateway refused it without calling upstream
	Reason   string        // why, when Denied
	Duration time.Duration // total time in the gateway, including upstream
}

// Config configures a Handler.
type Config struct {
	// Upstreams maps a server name to its MCP endpoint URL. The agent
	// reaches a server at /{name}/mcp. Names not listed here do not exist.
	Upstreams map[string]*url.URL

	// MaxBodyBytes caps client request bodies. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// AllowedOrigins lists extra Origin header values to accept. Requests
	// without an Origin header (non-browser clients) and loopback origins
	// are always accepted; anything else is refused, as the MCP spec requires.
	AllowedOrigins []string

	// Transport is used for upstream calls. Nil means http.DefaultTransport.
	Transport http.RoundTripper

	// Logger receives one line per exchange. Nil means slog.Default().
	Logger *slog.Logger

	// OnEvent, if set, is called once per exchange after it completes.
	OnEvent func(Event)
}

// Handler is the gateway's http.Handler.
type Handler struct {
	cfg       Config
	mux       *http.ServeMux
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
		},
		Transport:     h.cfg.Transport,
		FlushInterval: -1, // SSE: forward every event as it arrives
		ErrorLog:      slog.NewLogLogger(h.cfg.Logger.Handler(), slog.LevelWarn),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(r.Context().Err(), context.Canceled) {
				return // the client went away; nobody to answer
			}
			h.cfg.Logger.Warn("upstream error", "server", name, "err", err)
			msg, _ := r.Context().Value(ctxKey{}).(Message)
			writeRPCError(w, http.StatusBadGateway, msg.ID,
				&rpcError{codeUpstreamError, "MCP Guard: upstream server unavailable"})
		},
	}
}

func (h *Handler) serveMCP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	name := r.PathValue("server")
	rec := &statusRecorder{ResponseWriter: w}
	ev := Event{Server: name}

	defer func() {
		ev.Status = rec.status()
		ev.Duration = time.Since(start)
		h.cfg.Logger.Info("mcp exchange",
			"server", ev.Server,
			"http_method", r.Method,
			"kind", string(ev.Message.Kind),
			"rpc_method", ev.Message.Method,
			"tool", ev.Message.Tool,
			"status", ev.Status,
			"denied", ev.Denied,
			"reason", ev.Reason,
			"duration_ms", ev.Duration.Milliseconds(),
		)
		if h.cfg.OnEvent != nil {
			h.cfg.OnEvent(ev)
		}
	}()

	deny := func(status int, e *rpcError) {
		ev.Denied, ev.Reason = true, e.Message
		writeRPCError(rec, status, ev.Message.ID, e)
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
		// Forward exactly the bytes that were inspected.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, msg))

	case http.MethodGet, http.MethodDelete:
		// Pre-2026-07-28 revisions: GET opens the server-to-client SSE
		// stream and DELETE ends a session. Neither carries a client
		// message, so there is nothing to inspect. Newer servers answer 405.

	default:
		rec.Header().Set("Allow", "POST, GET, DELETE")
		deny(http.StatusMethodNotAllowed, &rpcError{codeInvalidRequest, "MCP Guard: method not allowed"})
		return
	}

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
