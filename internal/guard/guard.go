// Package guard connects the policy engine to the proxy. It is the only
// place that knows about both, which keeps the proxy free of policy imports.
package guard

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TangeniI/MCP-Guard-/internal/approval"
	"github.com/TangeniI/MCP-Guard-/internal/audit"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
	"github.com/TangeniI/MCP-Guard-/internal/scan"
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
		NeedsApproval:   d.NeedsApproval,
		Agent:           d.Agent,
		Code:            string(d.Code),
		Reason:          d.Reason,
		PolicyVersion:   d.PolicyHash,
	}
}

// BrokerApprover adapts an approval.Broker to proxy.Approver.
type BrokerApprover struct {
	Broker *approval.Broker
}

// RequestApproval implements proxy.Approver.
func (a BrokerApprover) RequestApproval(ctx context.Context, r proxy.ApprovalRequest) proxy.ApprovalOutcome {
	out := a.Broker.Ask(ctx, approval.Call{
		Agent:     r.Agent,
		Server:    r.Server,
		Tool:      r.Message.Tool,
		Arguments: r.Message.Arguments,
	})
	res := proxy.ApprovalOutcome{Approved: out.Approved, Code: out.Code, ID: out.ID, By: out.By, Wait: out.Waited}
	switch out.Code {
	case approval.CodeApproved:
	case approval.CodeDenied:
		res.Reason = "a human reviewer denied this call"
	case approval.CodeTimeout:
		res.Reason = fmt.Sprintf("no human approved this call within %s", a.Broker.Timeout())
	case approval.CodeCancelled:
		res.Reason = "the request was cancelled before a human decided"
	case approval.CodeQueueFull:
		res.Reason = "too many calls are already waiting for human approval"
	case approval.CodeTooLarge:
		res.Reason = "the arguments are too large for a human to review"
	default:
		res.Approved = false
		res.Reason = "approval failed"
	}
	return res
}

// AuditRecorder adapts an audit.Log to proxy.Recorder.
type AuditRecorder struct {
	Log *audit.Log
}

// Record implements proxy.Recorder.
func (a AuditRecorder) Record(e proxy.Event) error {
	return a.Log.Append(audit.Record{
		Time:           e.Time,
		Server:         e.Server,
		Agent:          e.Agent,
		HTTPMethod:     e.HTTPMethod,
		Kind:           string(e.Message.Kind),
		RPCMethod:      e.Message.Method,
		RPCID:          audit.RawID(e.Message.ID),
		Tool:           e.Message.Tool,
		Arguments:      e.Message.Arguments,
		Allowed:        !e.Denied,
		Code:           e.Code,
		Reason:         e.Reason,
		PolicyVersion:  e.PolicyVersion,
		ApprovalID:     e.ApprovalID,
		ApprovedBy:     e.ApprovedBy,
		ApprovalWaitUS: e.ApprovalWait.Microseconds(),
		Scanned:        e.Scanned,
		Quarantined:    e.Quarantined,
		ScanVerdict:    e.ScanVerdict,
		ScanSource:     e.ScanSource,
		ScanRule:       e.ScanRule,
		ScanDetail:     e.ScanDetail,
		ScanUS:         e.ScanDuration.Microseconds(),
		ResultBytes:    e.ResultBytes,
		ResultSHA256:   e.ResultSHA256,
		ToolsListed:    e.ToolsListed,
		ToolsHidden:    e.ToolsHidden,
		Status:         e.Status,
		DurationUS:     e.Duration.Microseconds(),
		UpstreamUS:     e.UpstreamDuration.Microseconds(),
	})
}

// ResultScanner adapts a scan.Scanner to proxy.Scanner.
type ResultScanner struct {
	Scanner *scan.Scanner
}

// ScanResult implements proxy.Scanner.
func (a ResultScanner) ScanResult(ctx context.Context, in proxy.ScanInput) proxy.ScanOutcome {
	res := a.Scanner.Scan(ctx, in.Texts)
	return proxy.ScanOutcome{
		Clean:    res.Verdict == scan.Clean,
		Verdict:  string(res.Verdict),
		Source:   res.Source,
		Rule:     res.Rule,
		Detail:   res.Detail,
		Duration: res.RulesDuration + res.JudgeDuration,
	}
}
