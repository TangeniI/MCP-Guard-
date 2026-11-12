package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fixed test tokens; only their hashes are configured.
const aliceToken = "test-approver-alice"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var testApprovers = map[string]string{
	"alice": sha256Hex(aliceToken),
	"bob":   sha256Hex("test-approver-bob"),
}

var sampleCall = Call{Agent: "alpha", Server: "files", Tool: "delete_file", Arguments: json.RawMessage(`{"path":"/workspace/a.txt"}`)}

// ask runs Ask in the background and returns a channel with its outcome,
// after the request has appeared in the queue.
func ask(t *testing.T, b *Broker, ctx context.Context, call Call) (Request, <-chan Outcome) {
	t.Helper()
	before := len(b.Pending())
	done := make(chan Outcome, 1)
	go func() { done <- b.Ask(ctx, call) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := b.Pending(); len(p) > before {
			return p[len(p)-1], done
		}
		select {
		case out := <-done:
			done <- out
			return Request{}, done
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request never appeared in the queue")
	return Request{}, nil
}

func wait(t *testing.T, done <-chan Outcome) Outcome {
	t.Helper()
	select {
	case out := <-done:
		return out
	case <-time.After(5 * time.Second):
		t.Fatal("Ask did not return")
		return Outcome{}
	}
}

func TestApproveAndDeny(t *testing.T) {
	b := NewBroker(time.Minute, 0)

	req, done := ask(t, b, context.Background(), sampleCall)
	if req.Agent != "alpha" || req.Tool != "delete_file" || string(req.Arguments) != `{"path":"/workspace/a.txt"}` {
		t.Errorf("queued request = %+v", req)
	}
	if err := b.Resolve(req.ID, true, "alice"); err != nil {
		t.Fatal(err)
	}
	out := wait(t, done)
	if !out.Approved || out.Code != CodeApproved || out.By != "alice" || out.ID != req.ID {
		t.Errorf("approved outcome = %+v", out)
	}
	// The decision is final: it cannot be made twice or reversed.
	if err := b.Resolve(req.ID, false, "bob"); err != ErrNotFound {
		t.Errorf("second decision: err = %v, want ErrNotFound", err)
	}
	if n := len(b.Pending()); n != 0 {
		t.Errorf("%d requests still pending", n)
	}

	req, done = ask(t, b, context.Background(), sampleCall)
	if err := b.Resolve(req.ID, false, "bob"); err != nil {
		t.Fatal(err)
	}
	out = wait(t, done)
	if out.Approved || out.Code != CodeDenied || out.By != "bob" {
		t.Errorf("denied outcome = %+v", out)
	}
}

func TestEveryNonApprovalRefuses(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		b := NewBroker(30*time.Millisecond, 0)
		out := b.Ask(context.Background(), sampleCall)
		if out.Approved || out.Code != CodeTimeout {
			t.Errorf("outcome = %+v", out)
		}
		if len(b.Pending()) != 0 {
			t.Error("timed-out request is still pending")
		}
		// A late approval finds nothing to approve.
		if err := b.Resolve(out.ID, true, "alice"); err != ErrNotFound {
			t.Errorf("late approval: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("agent hangs up", func(t *testing.T) {
		b := NewBroker(time.Minute, 0)
		ctx, cancel := context.WithCancel(context.Background())
		_, done := ask(t, b, ctx, sampleCall)
		cancel()
		out := wait(t, done)
		if out.Approved || out.Code != CodeCancelled {
			t.Errorf("outcome = %+v", out)
		}
		if len(b.Pending()) != 0 {
			t.Error("cancelled request is still pending")
		}
	})

	t.Run("queue full", func(t *testing.T) {
		b := NewBroker(time.Minute, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ask(t, b, ctx, sampleCall)
		ask(t, b, ctx, sampleCall)
		out := b.Ask(ctx, sampleCall)
		if out.Approved || out.Code != CodeQueueFull {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("arguments too large to review", func(t *testing.T) {
		b := NewBroker(time.Minute, 0)
		big := Call{Agent: "alpha", Server: "files", Tool: "write",
			Arguments: json.RawMessage(`{"text":"` + strings.Repeat("a", MaxArgumentBytes) + `"}`)}
		out := b.Ask(context.Background(), big)
		if out.Approved || out.Code != CodeTooLarge {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("unknown id", func(t *testing.T) {
		b := NewBroker(time.Minute, 0)
		if err := b.Resolve("no-such-id", true, "alice"); err != ErrNotFound {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

func adminRequest(t *testing.T, a *Admin, method, path, token string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestAdminAPI(t *testing.T) {
	b := NewBroker(time.Minute, 0)
	a, err := NewAdmin(b, testApprovers)
	if err != nil {
		t.Fatal(err)
	}
	req, done := ask(t, b, context.Background(), sampleCall)

	// No token, a wrong token, an agent's token and the hash itself are
	// all refused, for reading and for deciding.
	for _, token := range []string{"", "wrong", "test-token-alpha", testApprovers["alice"]} {
		for _, call := range [][2]string{
			{http.MethodGet, "/api/approvals"},
			{http.MethodPost, "/api/approvals/" + req.ID + "/approve"},
			{http.MethodPost, "/api/approvals/" + req.ID + "/deny"},
		} {
			rec, _ := adminRequest(t, a, call[0], call[1], token)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with token %q: status %d, want 401", call[0], call[1], token, rec.Code)
			}
		}
	}
	if len(b.Pending()) != 1 {
		t.Fatal("an unauthenticated request changed the queue")
	}

	// An approver sees the call exactly as it will be sent.
	rec, body := adminRequest(t, a, http.MethodGet, "/api/approvals", aliceToken)
	if rec.Code != http.StatusOK || body["approver"] != "alice" {
		t.Fatalf("list: status %d body %v", rec.Code, body)
	}
	pending := body["pending"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending = %v", pending)
	}
	item := pending[0].(map[string]any)
	if item["tool"] != "delete_file" || item["agent"] != "alpha" || item["arguments"].(map[string]any)["path"] != "/workspace/a.txt" {
		t.Errorf("listed request = %v", item)
	}

	// Unknown actions and GET-to-approve do nothing.
	if rec, _ := adminRequest(t, a, http.MethodPost, "/api/approvals/"+req.ID+"/maybe", aliceToken); rec.Code != http.StatusNotFound {
		t.Errorf("unknown action: status %d", rec.Code)
	}
	if rec, _ := adminRequest(t, a, http.MethodGet, "/api/approvals/"+req.ID+"/approve", aliceToken); rec.Code == http.StatusOK {
		t.Error("GET must not approve")
	}
	if len(b.Pending()) != 1 {
		t.Fatal("a rejected admin call changed the queue")
	}

	// Approving records who did it.
	rec, _ = adminRequest(t, a, http.MethodPost, "/api/approvals/"+req.ID+"/approve", aliceToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: status %d", rec.Code)
	}
	if out := wait(t, done); !out.Approved || out.By != "alice" {
		t.Errorf("outcome = %+v", out)
	}
	// Deciding again is a 404, not a second decision.
	if rec, _ := adminRequest(t, a, http.MethodPost, "/api/approvals/"+req.ID+"/deny", aliceToken); rec.Code != http.StatusNotFound {
		t.Errorf("second decision: status %d, want 404", rec.Code)
	}
}

func TestAdminPage(t *testing.T) {
	a, err := NewAdmin(NewBroker(time.Minute, 0), testApprovers)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/": "MCP Guard approvals", "/app.js": "textContent", "/app.css": "color-scheme"} {
		rec, _ := adminRequest(t, a, http.MethodGet, path, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s: status %d", path, rec.Code)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Errorf("GET %s: weak Content-Security-Policy %q", path, csp)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: missing nosniff", path)
		}
	}
	// The page must never build HTML from data.
	js, _ := webFiles.ReadFile("web/app.js")
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if strings.Contains(string(js), banned) {
			t.Errorf("app.js uses %s", banned)
		}
	}
}

func TestNewAdminRejectsBadConfig(t *testing.T) {
	b := NewBroker(time.Minute, 0)
	good := testApprovers["alice"]
	tests := map[string]map[string]string{
		"no approvers":   {},
		"bad name":       {"a b": good},
		"token not hash": {"alice": aliceToken},
		"upper-case":     {"alice": strings.ToUpper(good)},
		"shared token":   {"alice": good, "bob": good},
	}
	for name, approvers := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewAdmin(b, approvers); err == nil {
				t.Error("want an error")
			}
		})
	}
	if _, err := NewAdmin(nil, testApprovers); err == nil {
		t.Error("nil broker accepted")
	}
}
