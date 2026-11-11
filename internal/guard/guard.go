// Package guard connects the policy engine to the proxy. It is the only
// place that knows about both, which keeps the proxy free of policy imports.
package guard

import (
	"net/http"

	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
)

// PolicyAuthorizer adapts a policy.Engine to proxy.Authorizer.
type PolicyAuthorizer struct {
	Engine *policy.Engine
}

// Authorize implements proxy.Authorizer.
func (a PolicyAuthorizer) Authorize(r proxy.AuthRequest) proxy.Decision {
	req := policy.Request{
		Token:     r.BearerToken,
		Server:    r.Server,
		Method:    r.Message.Method,
		Tool:      r.Message.Tool,
		Arguments: r.Message.Arguments,
	}
	switch {
	case r.HTTPMethod != http.MethodPost:
		req.Kind = policy.KindStream
	case r.Message.Kind == proxy.KindRequest:
		req.Kind = policy.KindRequest
	case r.Message.Kind == proxy.KindNotification:
		req.Kind = policy.KindNotification
	case r.Message.Kind == proxy.KindResponse:
		req.Kind = policy.KindResponse
	default:
		// Leave Kind empty: the engine denies kinds it does not know.
	}

	d := a.Engine.Decide(req)
	return proxy.Decision{
		Allow:           d.Allow,
		Unauthenticated: d.Code == policy.CodeUnauthenticated,
		Agent:           d.Agent,
		Code:            string(d.Code),
		Reason:          d.Reason,
		PolicyVersion:   d.PolicyHash,
	}
}
