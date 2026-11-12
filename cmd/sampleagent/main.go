// Command sampleagent is the scripted "agent" for the demo. It has no model:
// it makes a fixed series of tool calls through the gateway and prints what
// came back, so each layer of the gateway can be seen doing its job.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

type step struct {
	server, tool string
	args         map[string]any
	expect       string // what the demo policy should make of it
}

func main() {
	gateway := flag.String("gateway", "http://127.0.0.1:8080", "base URL of MCP Guard")
	token := flag.String("token", "demo-token-not-a-secret", "agent bearer token (the demo value is public)")
	wait := flag.Duration("wait", 20*time.Second, "how long to wait for the gateway to come up")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	httpClient := &http.Client{Transport: bearer{*token}}

	deadline := time.Now().Add(*wait)
	for {
		resp, err := http.Get(*gateway + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "gateway not reachable:", err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}

	sessions := map[string]*mcp.ClientSession{}
	for _, server := range []string{"notes", "math"} {
		client := mcp.NewClient(&mcp.Implementation{Name: "sample-agent", Version: "0.1.0"}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint: *gateway + "/" + server + "/mcp", HTTPClient: httpClient}, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "connect to %s: %v\n", server, err)
			os.Exit(1)
		}
		defer session.Close()
		sessions[server] = session

		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list tools on %s: %v\n", server, err)
			os.Exit(1)
		}
		names := make([]string, 0, len(tools.Tools))
		for _, t := range tools.Tools {
			names = append(names, t.Name)
		}
		fmt.Printf("%-5s tools visible: %s\n", server, strings.Join(names, ", "))
	}

	steps := []step{
		{"notes", "read_note", map[string]any{"id": "welcome"}, "allowed"},
		{"notes", "read_note", map[string]any{"id": "poisoned"}, "result quarantined (prompt injection)"},
		{"notes", "read_note", map[string]any{"id": "../secrets"}, "denied (argument rule)"},
		{"notes", "echo", map[string]any{"text": "hi"}, "denied (tool not in policy for this server)"},
		{"math", "add", map[string]any{"a": 2, "b": 40}, "allowed"},
		{"math", "echo", map[string]any{"text": "hello"}, "allowed"},
		{"math", "echo", map[string]any{"text": strings.Repeat("x", 300)}, "denied (argument too long)"},
	}
	fmt.Println()
	for _, s := range steps {
		res, err := sessions[s.server].CallTool(ctx, &mcp.CallToolParams{Name: s.tool, Arguments: s.args})
		outcome := ""
		switch {
		case err != nil:
			outcome = "transport error: " + err.Error()
		case res.IsError:
			outcome = "REFUSED  " + text(res)
		case res.StructuredContent != nil:
			outcome = fmt.Sprintf("OK       %v", res.StructuredContent)
		default:
			outcome = "OK       " + text(res)
		}
		if len(outcome) > 150 {
			outcome = outcome[:150] + "…"
		}
		fmt.Printf("%s.%s  [expect: %s]\n    %s\n", s.server, s.tool, s.expect, outcome)
	}
}

func text(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return strings.Join(strings.Fields(t.Text), " ")
		}
	}
	return ""
}
