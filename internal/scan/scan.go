// Package scan decides whether a tool result is safe to show to a model.
//
// Two layers, either or both: pattern rules (fast, free, predictable) and an
// optional LLM judge (slower, costs money, catches paraphrase). The judge is
// fail-closed: "unsure", an error, a timeout or an answer that cannot be read
// all count as not clean.
package scan

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
)

// Verdict is the outcome of a scan.
type Verdict string

const (
	Clean     Verdict = "clean"     // nothing found; safe to pass on
	Injection Verdict = "injection" // looks like instructions aimed at the agent
	Unsure    Verdict = "unsure"    // could not establish that it is clean
)

// Defaults.
const (
	DefaultJudgeTimeout = 15 * time.Second

	// DefaultMaxJudgeBytes bounds what is sent to the judge. Larger results
	// are not truncated (the unread part could hold the attack); they are
	// reported as Unsure.
	DefaultMaxJudgeBytes = 200 << 10
)

// Judge is a second opinion from a language model. It must return Clean only
// when it is confident; anything else, including an error, is not clean.
type Judge interface {
	// Name identifies the judge (for example the model id) in audit records.
	Name() string
	Classify(ctx context.Context, text string) (verdict Verdict, reason string, err error)
}

// Options configures a Scanner.
type Options struct {
	Rules         bool          // run the pattern rules
	Judge         Judge         // optional; consulted when the rules find nothing
	JudgeTimeout  time.Duration // zero means DefaultJudgeTimeout
	MaxJudgeBytes int           // zero means DefaultMaxJudgeBytes
}

// Result is what a scan concluded and how.
type Result struct {
	Verdict Verdict
	Source  string // "rules", "judge:<name>" or "none"
	Rule    string // rule id, when the rules matched
	Detail  string // match excerpt or the judge's reason; never shown to the model

	RulesDuration time.Duration
	JudgeDuration time.Duration
}

// Scanner scans tool results. It is safe for concurrent use.
type Scanner struct {
	opts Options
}

// New returns a Scanner. At least one layer must be enabled: a scanner that
// checks nothing would report everything as clean.
func New(opts Options) (*Scanner, error) {
	if !opts.Rules && opts.Judge == nil {
		return nil, errors.New("scan: neither rules nor a judge is enabled")
	}
	if opts.JudgeTimeout <= 0 {
		opts.JudgeTimeout = DefaultJudgeTimeout
	}
	if opts.MaxJudgeBytes <= 0 {
		opts.MaxJudgeBytes = DefaultMaxJudgeBytes
	}
	return &Scanner{opts: opts}, nil
}

// Scan examines the text segments of one tool result.
func (s *Scanner) Scan(ctx context.Context, texts []string) Result {
	res := Result{Verdict: Clean, Source: "none"}

	if s.opts.Rules {
		res.Source = "rules"
		start := time.Now()
		// Each segment alone, then all of them together: an instruction
		// may be split across fields.
		finding, found := Finding{}, false
		for _, t := range texts {
			if finding, found = matchRules(t); found {
				break
			}
		}
		if !found && len(texts) > 1 {
			finding, found = matchRules(strings.Join(texts, " "))
		}
		res.RulesDuration = time.Since(start)
		if found {
			res.Verdict, res.Rule, res.Detail = Injection, finding.Rule, finding.Excerpt
			return res
		}
	}

	if s.opts.Judge == nil {
		return res
	}
	joined := strings.Join(texts, "\n\n")
	if !hasLetters(joined) {
		return res // numbers and punctuation cannot carry an instruction
	}
	res.Source = "judge:" + s.opts.Judge.Name()
	if len(joined) > s.opts.MaxJudgeBytes {
		res.Verdict, res.Detail = Unsure, "result too large for the judge to read in full"
		return res
	}

	start := time.Now()
	judgeCtx, cancel := context.WithTimeout(ctx, s.opts.JudgeTimeout)
	verdict, reason, err := s.opts.Judge.Classify(judgeCtx, joined)
	cancel()
	res.JudgeDuration = time.Since(start)

	switch {
	case err != nil:
		res.Verdict, res.Detail = Unsure, "judge failed: "+err.Error()
	case verdict == Clean:
		res.Verdict, res.Detail = Clean, reason
	case verdict == Injection:
		res.Verdict, res.Detail = Injection, reason
	default: // Unsure, or anything a faulty judge might return
		res.Verdict, res.Detail = Unsure, reason
	}
	return res
}

func hasLetters(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
