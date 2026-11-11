package policy

import "errors"

// ---------------------------------------------------------------------------
// HAND-WRITTEN PIECE — NOT TO BE WRITTEN BY AI (see CLAUDE.md).
//
// The argument-constraint matcher and its tests are written by hand. Until
// then this stub denies every call to a tool that has an "arguments" section,
// so the gateway fails closed.
//
// Contract the engine relies on:
//
//   - tool.Arguments is non-nil (the engine does not call the matcher for
//     tools without an "arguments" section).
//   - args is the call's params.arguments decoded with json.Number for
//     numbers; it is empty, never nil, when the call has no arguments.
//   - Return nil only if every constraint holds. Any other outcome,
//     including "cannot tell", must return an error; its text is shown to
//     the agent and written to the audit log.
//   - Arguments not named in tool.Arguments are denied unless
//     tool.AllowOtherArguments is true.
//   - Constraint.Regexp is the compiled Pattern when Pattern is set.
//
// Things that are easy to get subtly wrong (worth a test each): path_under
// against "..", "//", symlink-free lexical cleaning and the "/workspace-evil"
// prefix trap; email_domain against "a@evil.com@example.com", sub-domains
// and case; equals/one_of across json.Number vs float64; non-string values
// given to string constraints; whether a listed argument may be absent.
// ---------------------------------------------------------------------------

var errMatcherNotImplemented = errors.New("argument rules are configured but the argument matcher is not implemented yet")

func matchArguments(tool *Tool, args map[string]any) error {
	_ = tool
	_ = args
	return errMatcherNotImplemented
}
