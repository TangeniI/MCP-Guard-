// Package approval holds tool calls that need a human decision.
//
// A call waits in the Broker until a person approves or denies it. Every
// way of not getting an explicit "approve" — a denial, a timeout, the agent
// hanging up, a full queue — ends in the call being refused.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Defaults.
const (
	DefaultTimeout    = 2 * time.Minute
	DefaultMaxPending = 100

	// MaxArgumentBytes bounds what a reviewer is asked to read. A call
	// whose arguments are larger cannot be reviewed properly, so it is
	// refused rather than shown truncated.
	MaxArgumentBytes = 32 << 10
)

// Outcome codes. They appear in the audit log.
const (
	CodeApproved  = "approved"
	CodeDenied    = "approval_denied"
	CodeTimeout   = "approval_timeout"
	CodeCancelled = "approval_cancelled"
	CodeQueueFull = "approval_queue_full"
	CodeTooLarge  = "approval_too_large"
)

// ErrNotFound means the request does not exist or was already resolved.
var ErrNotFound = errors.New("approval: no such pending request")

// Call is the tool call a human is asked about.
type Call struct {
	Agent     string          `json:"agent"`
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"` // exactly what will be sent if approved
}

// Request is a Call waiting for a decision.
type Request struct {
	ID string `json:"id"`
	Call
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// Outcome is how a request ended.
type Outcome struct {
	Approved bool
	Code     string
	By       string        // who decided; empty unless a human did
	ID       string        // request ID; empty if it was never queued
	Waited   time.Duration // how long the call was held
}

type resolution struct {
	approved bool
	by       string
}

type pending struct {
	req  Request
	done chan resolution // buffered, written at most once
}

// Broker queues calls for human decisions. It is safe for concurrent use.
type Broker struct {
	timeout    time.Duration
	maxPending int

	mu      sync.Mutex
	pending map[string]*pending
}

// NewBroker returns a Broker. Zero values select the defaults.
func NewBroker(timeout time.Duration, maxPending int) *Broker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxPending <= 0 {
		maxPending = DefaultMaxPending
	}
	return &Broker{timeout: timeout, maxPending: maxPending, pending: make(map[string]*pending)}
}

// Timeout reports how long a call waits before it is refused.
func (b *Broker) Timeout() time.Duration { return b.timeout }

// Ask queues the call and blocks until a human decides, the timeout passes
// or ctx is cancelled. Only an explicit approval returns Approved.
func (b *Broker) Ask(ctx context.Context, call Call) Outcome {
	start := time.Now()
	if len(call.Arguments) > MaxArgumentBytes {
		return Outcome{Code: CodeTooLarge}
	}
	if call.Arguments == nil {
		call.Arguments = json.RawMessage("{}")
	}

	id, err := newID()
	if err != nil {
		return Outcome{Code: CodeQueueFull}
	}
	p := &pending{
		req:  Request{ID: id, Call: call, Created: start, Expires: start.Add(b.timeout)},
		done: make(chan resolution, 1),
	}

	b.mu.Lock()
	if len(b.pending) >= b.maxPending {
		b.mu.Unlock()
		return Outcome{Code: CodeQueueFull}
	}
	b.pending[id] = p
	b.mu.Unlock()

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()

	out := Outcome{ID: id}
	select {
	case res := <-p.done:
		out.Approved, out.By = res.approved, res.by
		out.Code = CodeDenied
		if res.approved {
			out.Code = CodeApproved
		}
	case <-timer.C:
		out = b.abandon(p, out, CodeTimeout)
	case <-ctx.Done():
		out = b.abandon(p, out, CodeCancelled)
	}
	out.Waited = time.Since(start)
	return out
}

// abandon withdraws a request nobody answered in time. If a human answered
// in the same instant, their answer stands only if it was a denial: an
// approval that raced with a timeout is not honoured.
func (b *Broker) abandon(p *pending, out Outcome, code string) Outcome {
	b.mu.Lock()
	delete(b.pending, p.req.ID)
	b.mu.Unlock()

	out.Code = code
	select {
	case res := <-p.done:
		out.By = res.by
		if !res.approved {
			out.Code = CodeDenied
		}
	default:
	}
	return out
}

// Pending lists the calls waiting for a decision, oldest first.
func (b *Broker) Pending() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := make([]Request, 0, len(b.pending))
	for _, p := range b.pending {
		list = append(list, p.req)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	return list
}

// Resolve records a human decision. The first decision wins; a second one,
// or one for a request that has expired, returns ErrNotFound.
func (b *Broker) Resolve(id string, approve bool, by string) error {
	b.mu.Lock()
	p, ok := b.pending[id]
	if ok {
		delete(b.pending, id)
	}
	b.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	p.done <- resolution{approved: approve, by: by}
	return nil
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
