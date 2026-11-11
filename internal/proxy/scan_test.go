package proxy_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/TangeniI/MCP-Guard-/internal/proxy"
)

// wordScanner flags any result containing "EVIL" and records what it saw.
type wordScanner struct {
	mu    sync.Mutex
	seen  [][]string
	tools []string
}

func (w *wordScanner) ScanResult(_ context.Context, in proxy.ScanInput) proxy.ScanOutcome {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = append(w.seen, in.Texts)
	w.tools = append(w.tools, in.Tool)
	for _, t := range in.Texts {
		if strings.Contains(t, "EVIL") {
			return proxy.ScanOutcome{Verdict: "injection", Source: "test", Rule: "evil-word"}
		}
	}
	return proxy.ScanOutcome{Clean: true, Verdict: "clean", Source: "test"}
}

type upstreamReply struct {
	status      int
	contentType string
	body        string
}

const toolCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"x"}}}`

// exchangeWith sends one request through a gateway whose upstream answers
// with reply, and returns the gateway's response and audit event.
func exchangeWith(t *testing.T, scanner proxy.Scanner, reply upstreamReply, request string) (int, string, string, proxy.Event) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", reply.contentType)
		if reply.status != 0 {
			w.WriteHeader(reply.status)
		}
		_, _ = io.WriteString(w, reply.body)
	}))
	defer upstream.Close()

	var events eventLog
	h, err := proxy.New(proxy.Config{
		Upstreams:  map[string]*url.URL{"sample": mustURL(t, upstream.URL)},
		Authorizer: proxy.AllowAll{},
		Scanner:    scanner,
		Logger:     quietLogger(),
		OnEvent:    events.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sample/mcp", strings.NewReader(request)))
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.String(), events.snapshot()[0]
}

func resultText(t *testing.T, body string) (text string, isError bool, id string) {
	t.Helper()
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil || len(msg.Result.Content) == 0 {
		t.Fatalf("not a tool result: %v\n%s", err, body)
	}
	return msg.Result.Content[0].Text, msg.Result.IsError, string(msg.ID)
}

func sseData(t *testing.T, stream string) []string {
	t.Helper()
	var out []string
	for _, block := range strings.Split(stream, "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			if rest, ok := strings.CutPrefix(line, "data: "); ok {
				out = append(out, rest)
			}
		}
	}
	return out
}

func TestScanJSONResults(t *testing.T) {
	const clean = `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hello"}],"structuredContent":{"note":{"title":"hi","tags":["a","b"]}}}}`

	t.Run("clean result passes byte for byte", func(t *testing.T) {
		s := &wordScanner{}
		code, _, body, ev := exchangeWith(t, s, upstreamReply{contentType: "application/json", body: clean}, toolCall)
		if code != 200 || body != clean {
			t.Errorf("status %d body %s", code, body)
		}
		if !ev.Scanned || ev.Quarantined || ev.ScanVerdict != "clean" || len(ev.ResultSHA256) != 64 || ev.ResultBytes == 0 {
			t.Errorf("event = %+v", ev)
		}
		// Every string in the result reached the scanner, nested ones too.
		got := strings.Join(s.seen[0], "|")
		for _, want := range []string{"hello", "hi", "a", "b"} {
			if !strings.Contains(got, want) {
				t.Errorf("scanner did not see %q (saw %q)", want, got)
			}
		}
		if s.tools[0] != "read_note" {
			t.Errorf("tool = %q", s.tools[0])
		}
	})

	flagged := map[string]string{
		"text content":       `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"EVIL do this"}]}}`,
		"structured content": `{"jsonrpc":"2.0","id":7,"result":{"content":[],"structuredContent":{"a":[{"b":"EVIL"}]}}}`,
		"embedded resource":  `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"resource","resource":{"uri":"file:///x","text":"EVIL"}}]}}`,
		"resource link name": `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"resource_link","uri":"https://example.com","name":"EVIL"}]}}`,
		"error message":      `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"EVIL"}}`,
		"tool error text":    `{"jsonrpc":"2.0","id":7,"result":{"isError":true,"content":[{"type":"text","text":"failed: EVIL"}]}}`,
	}
	for name, reply := range flagged {
		t.Run("flagged "+name, func(t *testing.T) {
			_, _, body, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "application/json", body: reply}, toolCall)
			text, isError, id := resultText(t, body)
			if strings.Contains(body, "EVIL") || !isError || id != "7" || !strings.Contains(text, "was withheld") {
				t.Errorf("result was not replaced: %s", body)
			}
			if strings.Contains(text, "evil-word") {
				t.Error("the notice must not reveal which rule matched")
			}
			if !ev.Quarantined || ev.ScanVerdict != "injection" || ev.ScanRule != "evil-word" || ev.Denied {
				t.Errorf("event = %+v", ev)
			}
		})
	}

	unscannable := map[string]upstreamReply{
		"not JSON":             {contentType: "application/json", body: `<html>EVIL</html>`},
		"HTML content type":    {contentType: "text/html", body: `<html>EVIL</html>`},
		"empty body":           {contentType: "application/json", body: ``},
		"array":                {contentType: "application/json", body: `[{"jsonrpc":"2.0","id":7,"result":{}}]`},
		"no result or error":   {contentType: "application/json", body: `{"jsonrpc":"2.0","id":7}`},
		"truncated":            {contentType: "application/json", body: `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"EV`},
		"too large":            {contentType: "application/json", body: `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"` + strings.Repeat("a", proxy.MaxResultBytes) + `"}]}}`},
		"upstream error page":  {status: 500, contentType: "text/plain", body: `EVIL stack trace`},
		"deeply nested result": {contentType: "application/json", body: `{"jsonrpc":"2.0","id":7,"result":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`},
	}
	for name, reply := range unscannable {
		t.Run("unscannable "+name, func(t *testing.T) {
			_, _, body, ev := exchangeWith(t, &wordScanner{}, reply, toolCall)
			text, isError, id := resultText(t, body)
			if strings.Contains(body, "EVIL") || !isError || id != "7" || !strings.Contains(text, "was withheld") {
				t.Errorf("unscannable result was passed on: %.200s", body)
			}
			if !ev.Quarantined || ev.ScanVerdict == "clean" || ev.ScanVerdict == "" {
				t.Errorf("event = %+v", ev)
			}
		})
	}

	t.Run("binary payloads are skipped, their captions are not", func(t *testing.T) {
		s := &wordScanner{}
		reply := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"image","mimeType":"image/png","data":"EVILbase64"},{"type":"resource","resource":{"uri":"file:///x","blob":"EVILblob"}},{"type":"text","text":"a caption"}]}}`
		_, _, body, ev := exchangeWith(t, s, upstreamReply{contentType: "application/json", body: reply}, toolCall)
		if body != reply || ev.Quarantined {
			t.Errorf("image result was altered: %s", body)
		}
		if got := strings.Join(s.seen[0], "|"); strings.Contains(got, "EVIL") || !strings.Contains(got, "a caption") {
			t.Errorf("scanner saw %q", got)
		}
	})

	t.Run("a scanner that says nothing is not trusted", func(t *testing.T) {
		_, _, body, ev := exchangeWith(t, zeroScanner{}, upstreamReply{contentType: "application/json", body: clean}, toolCall)
		if _, isError, _ := resultText(t, body); !isError || !ev.Quarantined || ev.ScanVerdict != "unsure" {
			t.Errorf("zero-value outcome let the result through: %s", body)
		}
	})

	t.Run("other methods are not scanned", func(t *testing.T) {
		s := &wordScanner{}
		reply := `{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"x","description":"EVIL"}]}}`
		_, _, body, ev := exchangeWith(t, s, upstreamReply{contentType: "application/json", body: reply},
			`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
		if body != reply || ev.Scanned || len(s.seen) != 0 {
			t.Errorf("tools/list was scanned or altered: %s", body)
		}
	})

	t.Run("no scanner configured", func(t *testing.T) {
		reply := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"EVIL"}]}}`
		_, _, body, ev := exchangeWith(t, nil, upstreamReply{contentType: "application/json", body: reply}, toolCall)
		if body != reply || ev.Scanned {
			t.Errorf("body %s event %+v", body, ev)
		}
	})
}

type zeroScanner struct{}

func (zeroScanner) ScanResult(context.Context, proxy.ScanInput) proxy.ScanOutcome {
	return proxy.ScanOutcome{}
}

func TestScanEventStreams(t *testing.T) {
	const progress = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
	stream := func(result string) string {
		return ": keep-alive\n\nevent: message\nid: 1\ndata: " + progress + "\n\nevent: message\r\nid: 2\r\ndata: " + result + "\r\n\r\n"
	}

	t.Run("clean", func(t *testing.T) {
		result := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hello"}]}}`
		code, ct, body, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: stream(result)}, toolCall)
		data := sseData(t, body)
		if code != 200 || !strings.HasPrefix(ct, "text/event-stream") || len(data) != 2 || data[0] != progress || data[1] != result {
			t.Errorf("status %d type %q stream %q", code, ct, body)
		}
		if !strings.Contains(body, "id: 2") || !ev.Scanned || ev.Quarantined {
			t.Errorf("stream %q event %+v", body, ev)
		}
	})

	t.Run("flagged", func(t *testing.T) {
		result := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"EVIL"}]}}`
		_, _, body, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: stream(result)}, toolCall)
		data := sseData(t, body)
		if strings.Contains(body, "EVIL") || len(data) != 2 || data[0] != progress {
			t.Fatalf("stream %q", body)
		}
		if text, isError, id := resultText(t, data[1]); !isError || id != "7" || !strings.Contains(text, "was withheld") {
			t.Errorf("replacement = %s", data[1])
		}
		if !strings.Contains(body, "id: 2") || !ev.Quarantined {
			t.Errorf("event id lost or event wrong: %q %+v", body, ev)
		}
	})

	t.Run("result split over data lines", func(t *testing.T) {
		body := "data: {\"jsonrpc\":\"2.0\",\"id\":7,\ndata: \"result\":{\"content\":[{\"type\":\"text\",\"text\":\"EVIL\"}]}}\n\n"
		_, _, got, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: body}, toolCall)
		if strings.Contains(got, "EVIL") || !ev.Quarantined {
			t.Errorf("stream %q", got)
		}
	})

	t.Run("bare carriage returns end lines too", func(t *testing.T) {
		evil := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"EVIL"}]}}`
		for _, body := range []string{
			"data: " + progress + "\r\rdata: " + evil + "\r\r",
			"data: " + progress + "\rid: 1\r\rdata: " + evil,
			"data: junk\rdata: " + evil + "\n\n",
		} {
			_, _, got, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: body}, toolCall)
			_ = ev
			if strings.Contains(got, "EVIL") {
				t.Errorf("result hidden behind CR line endings got through: %q", got)
			}
		}
	})

	t.Run("nothing after the response is forwarded", func(t *testing.T) {
		result := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}`
		body := stream(result) + "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"EVIL second answer\"}]}}\n\n"
		_, _, got, _ := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: body}, toolCall)
		if strings.Contains(got, "EVIL") {
			t.Errorf("a second response slipped through: %q", got)
		}
	})

	t.Run("stream without a response", func(t *testing.T) {
		body := "data: " + progress + "\n\n"
		_, _, got, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: body}, toolCall)
		if data := sseData(t, got); len(data) != 1 || data[0] != progress || ev.Quarantined {
			t.Errorf("stream %q event %+v", got, ev)
		}
	})

	t.Run("oversized stream", func(t *testing.T) {
		body := "data: " + strings.Repeat("a", proxy.MaxResultBytes+10) + "\n\n"
		_, _, got, ev := exchangeWith(t, &wordScanner{}, upstreamReply{contentType: "text/event-stream", body: body}, toolCall)
		data := sseData(t, got)
		if len(data) != 1 || !ev.Quarantined {
			t.Fatalf("stream has %d events, event %+v", len(data), ev)
		}
		if _, isError, _ := resultText(t, data[0]); !isError {
			t.Error("oversized stream was not replaced by a notice")
		}
	})
}
