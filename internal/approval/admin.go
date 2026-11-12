package approval

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

//go:embed web/index.html web/app.js web/app.css
var webFiles embed.FS

var (
	approverNameRE = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	sha256RE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Admin serves the approval page and its API.
//
// It must listen on a different address from the agent-facing gateway: an
// agent that could reach it could try to approve its own calls. Every API
// call needs an approver's bearer token; the page itself holds no data.
type Admin struct {
	broker    *Broker
	approvers map[string]string // sha256(token) -> approver name
	mux       *http.ServeMux
}

// NewAdmin builds the admin handler. approvers maps a person's name to the
// lower-case hex SHA-256 of their token.
func NewAdmin(broker *Broker, approvers map[string]string) (*Admin, error) {
	if broker == nil {
		return nil, errors.New("approval: no broker")
	}
	if len(approvers) == 0 {
		return nil, errors.New("approval: no approvers configured")
	}
	a := &Admin{broker: broker, approvers: make(map[string]string, len(approvers)), mux: http.NewServeMux()}
	for name, hash := range approvers {
		if !approverNameRE.MatchString(name) {
			return nil, fmt.Errorf("approval: invalid approver name %q", name)
		}
		if !sha256RE.MatchString(hash) {
			return nil, fmt.Errorf("approval: approver %q needs a 64-character lower-case hex SHA-256", name)
		}
		if other, dup := a.approvers[hash]; dup {
			return nil, fmt.Errorf("approval: approvers %q and %q share a token", other, name)
		}
		a.approvers[hash] = name
	}

	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		return nil, err
	}
	a.mux.Handle("GET /", http.FileServerFS(static))
	a.mux.HandleFunc("GET /api/approvals", a.list)
	a.mux.HandleFunc("POST /api/approvals/{id}/{action}", a.resolve)
	return a, nil
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Arguments shown on the page are chosen by the agent, so the page
	// treats them as hostile: no inline script, no framing, no sniffing.
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	a.mux.ServeHTTP(w, r)
}

// approver identifies the caller from the Authorization header.
func (a *Admin) approver(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	name, ok := a.approvers[hex.EncodeToString(sum[:])]
	return name, ok
}

func (a *Admin) list(w http.ResponseWriter, r *http.Request) {
	name, ok := a.approver(r)
	if !ok {
		unauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approver":        name,
		"timeout_seconds": int(a.broker.Timeout().Seconds()),
		"pending":         a.broker.Pending(),
	})
}

func (a *Admin) resolve(w http.ResponseWriter, r *http.Request) {
	name, ok := a.approver(r)
	if !ok {
		unauthorized(w)
		return
	}
	var approve bool
	switch r.PathValue("action") {
	case "approve":
		approve = true
	case "deny":
		approve = false
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown action"})
		return
	}
	if err := a.broker.Resolve(r.PathValue("id"), approve, name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found; it may have expired or been decided already"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approved": approve, "by": name})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-guard-admin"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "approver token required"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
