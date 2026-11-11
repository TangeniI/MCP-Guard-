// Package sampleserver is a tiny MCP server used by the integration tests and
// the local demo. It holds no real data and needs no credentials.
package sampleserver

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EchoArgs is the input of the echo tool.
type EchoArgs struct {
	Text string `json:"text" jsonschema:"text to send back"`
}

// AddArgs is the input of the add tool.
type AddArgs struct {
	A float64 `json:"a" jsonschema:"first number"`
	B float64 `json:"b" jsonschema:"second number"`
}

// AddResult is the structured output of the add tool.
type AddResult struct {
	Sum float64 `json:"sum"`
}

// New returns an MCP server with two harmless tools: echo and add.
func New() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-guard-sample", Version: "0.1.0"}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Return the given text unchanged"},
		func(_ context.Context, _ *mcp.CallToolRequest, in EchoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "add", Description: "Add two numbers"},
		func(_ context.Context, _ *mcp.CallToolRequest, in AddArgs) (*mcp.CallToolResult, AddResult, error) {
			return nil, AddResult{Sum: in.A + in.B}, nil
		})

	return s
}

// Handler serves New() over Streamable HTTP.
func Handler() http.Handler {
	s := New()
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
