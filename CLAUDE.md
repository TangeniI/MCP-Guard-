# CLAUDE.md: MCP Guard (measured security gateway for AI agent tools, in Go)

## What this is

A small, auditable gateway that sits between an AI agent and its MCP servers. Every tool call goes
through it. It enforces least-privilege policies, asks a human before dangerous actions, scans tool
results for prompt injection, and logs everything.

It applies Agent Spend Guard's idea ("the agent proposes; rules and a human decide") to any tool,
and uses ClearPass's attack knowledge to test it.

## Be honest about the landscape

MCP gateways are a crowded space in 2026, with many commercial and open-source options. Another
gateway is not news. **The contribution here is the measurement:** a reproducible, public score on
a recognised benchmark, with the misses published. Most gateway pages claim security; few show numbers.

So the README leads with the results table, not the feature list.

## Why (the gap it closes)

- AI-native roles ask about agent loops, MCP, tool permissions and security. micro1 asked how to
  enforce rules with automated checks.
- Go appears in 19.4% of UK postings, and proxies are what Go is used for. This is the second Go
  project, so it deepens Ledgerline's skills.

## Features

1. **Proxy**: MCP over Streamable HTTP, plus a stdio wrapper. Invisible to agent and server.
2. **Policy engine**: YAML per agent identity. Allowed servers and tools, argument rules (for example
   `filesystem.write` only under `/workspace`, `email.send` only to one domain), rate limits.
   Default deny. An invalid policy stops startup.
3. **Approval**: tools marked `requires_approval` pause for a human (CLI or small web page). A timeout is a denial.
4. **Result scanning**: rules plus an optional LLM judge with a fail-closed "unsure" verdict. Flagged
   output is quarantined before the model sees it.
5. **Audit log**: every call, decision, policy version and latency. Append-only, exportable as JSON.
6. **Metrics**: Prometheus counters for calls, denials, approvals, scan hits and added latency.

## Stack

- Go 1.23+, `net/http`, `slog`, SQLite locally and Postgres optionally
- The official Go MCP SDK if it fits. **Check the current MCP spec and SDK versions first; don't rely on memory.**
- JSON Schema for policies; golden-file tests for decisions
- Fuzz tests (`go test -fuzz`) on the policy parser and argument matchers
- An architecture check in CI: the proxy package may not import the policy store directly
- Docker image, Helm chart, and a `docker compose` demo with a sample agent and two MCP servers

## Evaluation (the headline)

**1. AgentDojo.** A published benchmark for prompt-injection attacks on tool-using agents
(arXiv 2406.13352). Bridge its tools so calls pass through the gateway, then run the suites with the
guard off and on. Report, for a named model and date:
- Attack success rate, off vs on
- Benign task success, off vs on (the usability cost)
- Median added latency per call

**2. MCP-specific scenarios** (at least 50, in `evals/`): poisoned tool descriptions, a server that
changes its tools after approval, writes outside allowed paths, exfiltration through arguments, and
benign tasks that must still pass.

**3. Ablations.** Policies only; scanning only; both. Shows which layer does the work.

**4. Stretch.** Run the same suite against one existing open-source gateway and publish the
comparison fairly, with their configuration documented.

Publish `evals/results/*.json` and a "what still gets through" section.

## Decisions to record (ADRs)

- Why default deny, and what it costs in usability
- Rules vs an LLM judge for scanning: accuracy, latency, cost
- Where a gateway can't help (for example, a model that leaks data in its own text reply)

## Milestones

| Step | Done when |
|---|---|
| 1 | Proxy passes calls through; integration test with a sample server |
| 2 | Policy engine, default deny, fuzz tests |
| 3 | Approval flow and audit log |
| 4 | Result scanning with the fail-closed judge |
| 5 | AgentDojo bridge and first results table |
| 6 | MCP scenarios, ablations, "what still gets through" |
| 7 | Image, Helm chart, docs; share in MCP community channels; case study |

## Hand-written piece (no AI)

The **argument-constraint matcher** (does this tool call's arguments satisfy the policy?) and its tests.
Small, security-critical, and easy to get subtly wrong.

## Working rules for Claude Code

- Fail closed: unknown tool, bad policy, judge timeout, approval timeout all mean deny.
- No real credentials in examples or evals.
- Every number comes from a results file; record the model, version and date.
- Never tune rules against the test scenarios without holding some back. Keep a held-out set.
- Explain-back after each milestone.

## Defend it (answer without notes before it goes on the CV)

1. What is MCP, and what happens on the wire during a tool call?
2. What is a prompt injection through a tool result? Give a concrete example.
3. Why can't the model be trusted to police itself?
4. Why default deny? What did it cost in benign task success?
5. What still gets through your gateway, and why?
6. How did you avoid overfitting your rules to your own tests?
7. How does AgentDojo measure attack success?
8. How would you run this for 50 agents and 200 tools? What breaks first?

## CV line once done (real numbers only)

"**MCP Guard** (open source): security gateway for AI agent tools in Go, with least-privilege policies,
human approval, prompt-injection scanning and audit logs. On the AgentDojo benchmark it cut attack
success from X% to Y% with benign task success at Z%, adding ~N ms per call; misses published."
