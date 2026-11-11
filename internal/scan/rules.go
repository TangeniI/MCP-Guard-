package scan

import (
	"regexp"
	"strings"
	"unicode"
)

// A rule is one pattern that, in a tool result, suggests text written to
// steer an AI agent rather than to inform a reader.
//
// The rules describe general shapes of injection (override the instructions,
// impersonate the system, address the agent, hijack the task, hide from the
// user, exfiltrate). They deliberately contain no strings copied from any
// benchmark's attack templates: see CLAUDE.md, "never tune rules against the
// test scenarios without holding some back".
type rule struct {
	id string
	re *regexp.Regexp
}

const (
	agentNoun = `(?:ai|a\.i\.|assistant|agent|llm|language model|model|chatbot|bot|claude|chatgpt|gpt|gemini|copilot)`
	userNoun  = `(?:user|human|operator|owner|customer|person)`
	actVerb   = `(?:call|use|invoke|run|execute|send|forward|email|transfer|wire|pay|delete|remove|post|upload|visit|open|fetch|download|create|change|update|reset|share|book|buy|purchase)`
)

// Patterns run on normalised text: lower-case, invisible characters removed,
// whitespace collapsed to single spaces.
var rules = []rule{
	// Gaps allow only words and light punctuation, so code such as
	// ignore(previous, instructions) is not a match.
	{"instruction-override", regexp.MustCompile(
		`\b(?:ignore|disregard|forget|override|bypass|do not follow|don't follow|stop following)\b[\w ,:'’"-]{0,40}\b(?:previous|prior|above|earlier|preceding|all|any|your|the system|original|existing|current)\b[\w ,:'’"-]{0,30}\b(?:instructions?|prompts?|directives?|rules|guidelines|guidance|context|messages?|orders|programming)\b`)},

	{"role-impersonation", regexp.MustCompile(
		`<\|?(?:im_start|im_end|system|endoftext|start_header_id|eot_id)\|?>|\[/?inst\]|<<\s*/?sys\s*>>|</?(?:system|assistant)(?:[ _-]?(?:message|prompt))?>|###\s*(?:system|instructions?)\b|\bsystem (?:prompt|message|override|notice)\s*:|\bnew (?:system )?instructions?\s*:|\b(?:end|start) of (?:system )?(?:prompt|instructions)\b`)},

	{"agent-addressed", regexp.MustCompile(
		`\b(?:attention|important|urgent|notice|note|message|instructions?|memo)\b[^.]{0,30}\b(?:for|to)\b (?:the |an? |any |all )?` + agentNoun + `s?\b` +
			`|\b(?:dear|hey|hello|hi|ok|okay|listen),? ` + agentNoun + `\b[,:!]` +
			`|\bif you are (?:an? |the )?` + agentNoun + `\b` +
			`|\b(?:as|since you are|you are) an? (?:ai|llm|language model|automated) (?:assistant|agent|model|system)?\b[^.]{0,60}\b(?:must|should|need to|have to|are required to|are instructed to)\b`)},

	{"task-hijack", regexp.MustCompile(
		`\bbefore (?:you )?(?:can )?(?:continu\w*|proceed\w*|answer\w*|respond\w*|reply\w*|solv\w*|complet\w*|finish\w*|do(?:ing)? anything)\b[^.]{0,80}\b(?:you must|you need to|you should|you have to|please|first|do the following)\b` +
			`|\b(?:instead|first|now|immediately),? (?:you (?:must|should|need to|have to)|please) ` + actVerb + `\b` +
			`|\byour (?:new|real|actual|true|updated|primary|only) (?:task|goal|instructions?|objective|job|mission|purpose) (?:is|are)\b` +
			`|\b(?:do|perform|complete|carry out|follow) (?:the following|these) (?:steps |actions |instructions |tasks? )?(?:first|before|immediately|right now|now)\b` +
			`|\b(?:new|updated|additional|further) (?:task|instructions?|orders) from (?:the |your )?` + userNoun + `\b`)},

	{"secrecy", regexp.MustCompile(
		`\b(?:do not|don't|dont|never|without) (?:tell|telling|mention|mentioning|inform|informing|reveal|revealing|notify|notifying|alert|alerting|ask|asking|show|showing|disclos\w+|report\w*)\b[^.]{0,30}\b(?:the |your )?` + userNoun + `\b` +
			`|\bkeep (?:this|it|that) (?:a )?(?:secret|hidden|confidential|private) from (?:the |your )?` + userNoun + `\b` +
			`|\b(?:silently|secretly|quietly|covertly|discreetly) ` + actVerb + `\b`)},

	// Needs a destination (an address, URL, "to me"...), so advice such as
	// "never email your credentials to anyone" is not a match.
	{"exfiltration", regexp.MustCompile(
		`\b(?:send|forward|email|post|upload|transmit|leak|exfiltrate|share|copy|paste|submit|include|append)\b[^.]{0,80}\b(?:passwords?|credentials?|api[ _-]?keys?|access tokens?|auth(?:entication)? tokens?|secret keys?|private keys?|ssh keys?|session cookies?|2fa codes?|security codes?|verification codes?|credit card|card numbers?|bank details|conversation history|chat history|system prompt|environment variables)\b[^.]{0,80}(?:\b(?:to|at|via|into)\b[^.]{0,40}(?:https?://|www\.|@|\b(?:address|server|url|endpoint|webhook|number|inbox|account|site|link|me|us)\b)|\bin the url\b)`)},

	{"tool-call-markup", regexp.MustCompile(
		`<function_calls>|<invoke name=|</?tool_call>|</?tool_use>|<\|tool_call\|>`)},
}

// Finding is one rule match.
type Finding struct {
	Rule    string // rule id
	Excerpt string // normalised text around the match
}

// invisible reports characters that render as nothing and are used to split
// trigger words or to smuggle text past a reader.
func invisible(r rune) bool {
	switch {
	case r == 0x200B, r == 0x200C, r == 0x2060, r == 0xFEFF, r == 0x00AD:
		return true // zero-width space / non-joiner, word joiner, BOM, soft hyphen
	case r >= 0xE0000 && r <= 0xE007F:
		return true // Unicode tag characters: invisible ASCII look-alikes
	}
	return false
}

// bidiControl reports characters that reorder how text is displayed.
func bidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// normalise lower-cases, drops invisible characters and collapses whitespace
// so that patterns cannot be dodged with spacing, case or zero-width tricks.
func normalise(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case invisible(r) || bidiControl(r):
			continue
		case unicode.IsSpace(r):
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// hiddenText looks for characters that have no business in honest tool
// output: Unicode tag characters (an invisible copy of ASCII), bidirectional
// overrides, or a run of zero-width characters.
func hiddenText(s string) (Finding, bool) {
	zeroWidth := 0
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			return Finding{Rule: "hidden-text", Excerpt: "Unicode tag characters (invisible text)"}, true
		case bidiControl(r):
			return Finding{Rule: "hidden-text", Excerpt: "bidirectional override characters"}, true
		case r == 0x200B || r == 0x2060:
			zeroWidth++
		}
	}
	if zeroWidth >= 5 {
		return Finding{Rule: "hidden-text", Excerpt: "repeated zero-width characters"}, true
	}
	return Finding{}, false
}

// matchRules returns the first finding in text, if any.
func matchRules(text string) (Finding, bool) {
	if f, ok := hiddenText(text); ok {
		return f, true
	}
	norm := normalise(text)
	for _, r := range rules {
		if loc := r.re.FindStringIndex(norm); loc != nil {
			return Finding{Rule: r.id, Excerpt: excerpt(norm, loc[0], loc[1])}, true
		}
	}
	return Finding{}, false
}

// excerpt returns the match with a little context, cut on rune boundaries.
func excerpt(s string, start, end int) string {
	const context, limit = 40, 200
	from, to := max(0, start-context), min(len(s), end+context)
	if to-from > limit {
		to = from + limit
	}
	for from > 0 && !isRuneStart(s[from]) {
		from--
	}
	for to < len(s) && !isRuneStart(s[to]) {
		to++
	}
	return s[from:to]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
