package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// Tool definitions are attacker-controlled text too. A server can put
// instructions in a tool's description ("tool poisoning"), or show a
// harmless definition first and a different one later, after a human or a
// policy has accepted it (a "rug pull"). The gateway handles both on
// tools/list:
//
//   - each tool definition is scanned like a tool result; a flagged tool is
//     removed from the list and calls to it are refused;
//   - with pinning on, the first definition seen for a tool name is
//     remembered; if it later changes, the tool is removed and refused
//     until the gateway restarts.
//
// Pins live in memory and are "trust on first use": a server that is
// malicious from its first response is caught only by the scan.

// Reasons a tool is blocked. They appear in audit records.
const (
	toolPoisoned = "tool_poisoned"
	toolChanged  = "tool_changed"
)

type toolState struct {
	hash    string // SHA-256 of the definition first seen
	blocked string // "" or one of the reasons above
	detail  string // for the audit log
}

type toolRegistry struct {
	mu      sync.Mutex
	servers map[string]map[string]*toolState
}

func newToolRegistry() *toolRegistry {
	return &toolRegistry{servers: make(map[string]map[string]*toolState)}
}

// blocked reports whether calls to a tool must be refused, and why.
func (r *toolRegistry) blocked(server, tool string) (reason, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.servers[server][tool]; st != nil {
		return st.blocked, st.detail
	}
	return "", ""
}

// hashJSON hashes a JSON value independently of key order and spacing.
func hashJSON(raw json.RawMessage) (string, bool) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "", false
	}
	canonical, err := json.Marshal(v) // Go writes object keys in sorted order
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), true
}

// filterToolList processes one tools/list response and returns the bytes to
// send on, with blocked tools removed. A response it cannot read becomes an
// empty tool list: the agent sees no tools rather than unvetted ones.
func (h *Handler) filterToolList(ctx context.Context, st *exchange, raw []byte) []byte {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return h.withhold(st, nil, "unparseable", "tools/list response is not a JSON object")
	}
	if _, isError := fields["error"]; isError {
		if _, hasResult := fields["result"]; !hasResult {
			return raw // the server refused to list tools; nothing to vet
		}
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(fields["result"], &result); err != nil {
		return h.withhold(st, fields["id"], "unparseable", "tools/list result is not an object")
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil {
		return h.withhold(st, fields["id"], "unparseable", "tools/list result has no tools array")
	}

	st.scanned = true
	kept := make([]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		var head struct {
			Name string `json:"name"`
		}
		hash, ok := hashJSON(tool)
		if json.Unmarshal(tool, &head) != nil || head.Name == "" || !ok {
			st.toolsHidden = append(st.toolsHidden, "(unnamed): unparseable")
			continue
		}
		if reason := h.vetTool(ctx, st, head.Name, hash, tool); reason != "" {
			st.toolsHidden = append(st.toolsHidden, head.Name+": "+reason)
			continue
		}
		kept = append(kept, tool)
	}
	st.toolsListed = len(kept)
	if len(kept) == len(tools) {
		return raw // nothing removed: pass the original bytes untouched
	}

	result["tools"], _ = json.Marshal(kept)
	fields["result"], _ = json.Marshal(result)
	out, err := json.Marshal(fields)
	if err != nil {
		return h.withhold(st, fields["id"], "unparseable", "could not rebuild the tool list")
	}
	return out
}

// vetTool decides whether one tool definition may be shown. It returns the
// blocking reason, or "" if the tool is fine.
func (h *Handler) vetTool(ctx context.Context, st *exchange, name, hash string, def json.RawMessage) string {
	reg := h.tools
	reg.mu.Lock()
	known := reg.servers[st.server][name]
	reg.mu.Unlock()

	if known != nil {
		switch {
		case known.blocked != "":
			return known.blocked // once blocked, blocked until restart
		case known.hash == hash:
			return ""
		case h.cfg.PinTools:
			reg.mu.Lock()
			known.blocked, known.detail = toolChanged, "definition differs from the one first seen"
			reg.mu.Unlock()
			return toolChanged
		}
		// Not pinning: treat the new definition as new, and vet it below.
	}

	state := &toolState{hash: hash}
	if h.cfg.Scanner != nil {
		texts, err := collectStrings(def)
		outcome := ScanOutcome{Verdict: "unparseable"}
		if err == nil {
			outcome = h.cfg.Scanner.ScanResult(ctx, ScanInput{Server: st.server, Agent: st.agent, Tool: name, Texts: texts})
			st.scan.Duration += outcome.Duration
		}
		if !outcome.Clean {
			state.blocked, state.detail = toolPoisoned, outcome.Rule+" "+outcome.Detail
		}
	}

	reg.mu.Lock()
	if reg.servers[st.server] == nil {
		reg.servers[st.server] = make(map[string]*toolState)
	}
	reg.servers[st.server][name] = state
	reg.mu.Unlock()
	return state.blocked
}

// emptyToolList is the fail-closed answer to a tools/list the gateway could
// not vet.
func emptyToolList(id json.RawMessage) []byte {
	if len(id) == 0 || !json.Valid(id) {
		id = json.RawMessage("null")
	}
	body, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  map[string]any  `json:"result"`
	}{"2.0", id, map[string]any{"tools": []any{}}})
	return body
}
