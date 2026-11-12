# MCP Guard

A small security gateway that sits between an AI agent and its MCP servers. Every tool call goes through it.
It enforces a least-privilege policy, asks a human before dangerous actions, scans what tools return for
prompt injection, and keeps an append-only audit log.

There are many MCP gateways. This one's contribution is that it is **measured**, and that the misses are
published next to the hits.

## Results

Every number below comes from a file in [`evals/results/`](evals/results/). How each was produced, and what it
does not show, is in [`evals/README.md`](evals/README.md). What gets through is in
[`docs/what-still-gets-through.md`](docs/what-still-gets-through.md).

### MCP-specific scenarios (no model)

82 scenarios played against the real gateway code: 60 attacks and 22 benign tasks. 45 of them are held out,
meaning the rules were never adjusted against them. An attack counts as blocked only if the harmful effect was
impossible. Source: `scenarios-20261112-125453.json`.

| Gateway configuration | Attacks blocked (all) | Attacks blocked (held out) | Benign tasks working (all) | Benign working (held out) |
|---|---|---|---|---|
| Off | 0 / 60 | 0 / 32 | 22 / 22 | 13 / 13 |
| Policy only | 28 / 60 | 14 / 32 | 22 / 22 | 13 / 13 |
| Content only (scanning + tool pinning) | 17 / 60 | 3 / 32 | 20 / 22 | 11 / 13 |
| Both | **45 / 60** | **17 / 32** | **20 / 22** | **11 / 13** |

By kind of attack, with both layers on:

| Attack | Blocked (all) | Blocked (held out) | Layer that does the work |
|---|---|---|---|
| Reads and writes outside allowed paths | 10 / 10 | 5 / 5 | Policy |
| Exfiltration through arguments | 14 / 16 | 7 / 9 | Policy |
| Tools the agent was never granted | 4 / 4 | 2 / 2 | Policy |
| Tool definition changed after first sight | 6 / 6 | 3 / 3 | Content (pinning) |
| Poisoned tool descriptions | 5 / 10 | 0 / 5 | Content (scanning) |
| Prompt injection in tool results | 6 / 14 | 0 / 8 | Content (scanning) |

The pattern is clear: the policy layer generalises, because it checks structure. The scanning layer does not:
it caught every phrasing it was written with and none of the held-out rewordings.

### AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (arXiv 2406.13352), benchmark v1.2.2: 97 user tasks and
949 attack pairs, `important_instructions` attack. Every tool call is routed through the gateway.

<!-- agentdojo-table:start -->
| Agent model | Guard | Benign utility | Utility under attack | Attack success | Injected results quarantined | Benign results quarantined | Benign calls denied | Added ms per call (median of suite medians / worst suite p95) | Date | File |
|---|---|---|---|---|---|---|---|---|---|---|
| none (scripted) | off | 100.0% (97/97) | 100.0% (949/949) | not measurable | 0.0% (0/1234) | 0.0% (0/339) | 0.0% (0/339) | 0.009 / 0.042 | 2026-11-11 | agentdojo-20261111-172311-ground-truth-guard-off.json |
| none (scripted) | scan: rules | 100.0% (97/97) | 100.0% (949/949) | not measurable | 100.0% (1234/1234) | 0.0% (0/339) | 0.0% (0/339) | 0.173 / 5.707 | 2026-11-11 | agentdojo-20261111-172405-ground-truth-guard-scan.json |
| none (scripted) | policy: per-task (oracle) | 100.0% (97/97) | 100.0% (949/949) | not measurable | 0.0% (0/1234) | 0.0% (0/339) | 0.0% (0/339) | 0.013 / 0.062 | 2026-11-11 | agentdojo-20261111-172458-ground-truth-guard-policy-oracle-task-policy.json |
| none (scripted) | policy: suite allow-list; scan: rules | 100.0% (97/97) | 100.0% (949/949) | not measurable | 100.0% (1234/1234) | 0.0% (0/339) | 0.0% (0/339) | 0.195 / 5.807 | 2026-11-11 | agentdojo-20261111-172601-ground-truth-guard-both.json |
| gemini-3.5-flash-lite — banking (4 tasks, 12 pairs) | off | 100.0% (4/4) | 50.0% (6/12) | 0.0% (0/12) | 0.0% (0/15) | 0.0% (0/10) | 0.0% (0/10) | 0.104 / 0.553 | 2026-11-12 (partial) | agentdojo-20261112T124857Z-gemini-3.5-flash-lite-guard-off-pilot.json |
| gemini-3.5-flash-lite — banking (4 tasks, 12 pairs) | scan: rules | 100.0% (4/4) | 0.0% (0/12) | 0.0% (0/12) | 100.0% (13/13) | 0.0% (0/11) | 0.0% (0/11) | 0.689 / 3.751 | 2026-11-12 (partial) | agentdojo-20261112T125822Z-gemini-3.5-flash-lite-guard-scan-pilot.json |
<!-- agentdojo-table:end -->

Read these with care:

- **The scripted agent has no model.** It replays each task's known-correct tool calls, so it cannot be
  fooled. Its rows show that the wiring is sound and what the gateway does to tool traffic, not whether
  attacks succeed.
- **"Injected results quarantined: 100%" is one fixed public template** matched by one rule. See the held-out
  figures above for how the same rules do on wording they were not written for.
- **Model runs so far are small pilots** on a free tier; they are labelled partial and are not a benchmark
  score.
- **The pilot shows the cost, not the benefit.** On a 4-task, 12-attack slice of the banking suite,
  `gemini-3.5-flash-lite` resisted all 12 attacks with the gateway off, so there was nothing for the gateway
  to reduce. With rules scanning on, every injected result was quarantined (13 of 13) and the share of user
  tasks still completed under attack fell from 6 of 12 to 0 of 12: withholding a whole tool result also
  withholds the data the task needed. Benign tasks with no attack present were unaffected (4 of 4 both ways).

## What it does

| Layer | What it does | Fails closed when |
|---|---|---|
| Proxy | MCP over Streamable HTTP, and stdio servers started by the gateway. Strictly parses every client message. | A message is malformed, has duplicate keys, or its headers disagree with its body |
| Policy | YAML per agent identity: servers, tools, argument rules, rate limits. Default deny. | The policy is invalid (the gateway will not start), or anything is not listed |
| Approval | Tools marked `requires_approval` wait for a human on a separate page. | Nobody answers in time, the agent hangs up, or no approver is configured |
| Scanning | Rules, plus an optional LLM judge, over tool results and tool descriptions. Flagged output is withheld. | The judge is unsure, errors or times out; a result cannot be parsed or is too large |
| Tool pinning | Remembers each tool's first definition; blocks a tool that changes. | A definition differs from the one first seen |
| Audit | Every exchange, decision, policy version and latency in a hash-chained SQLite log. Exportable as JSON Lines. | The log cannot be written (the gateway stops forwarding) |
| Metrics | Prometheus counters and an added-latency histogram. | n/a |

## Try it

Needs Go 1.25 or later.

```bash
go run ./cmd/sampleserver -listen 127.0.0.1:9001
```

```bash
go run ./cmd/mcpguard -policy examples/policy.yaml -upstream sample=http://127.0.0.1:9001
```

The agent's MCP endpoint is then `http://127.0.0.1:8080/sample/mcp`, with the bearer token
`demo-token-not-a-secret` (a public demo value; the policy holds only its hash).

A scripted demo with two MCP servers and each layer visibly doing its job:

```bash
docker compose -f deploy/compose/docker-compose.yml up --build --abort-on-container-exit
```

### A policy

```yaml
version: 1
agents:
  - name: research-agent
    token_sha256: <sha256 of the agent's token>
    servers:
      files:
        tools:
          read_file:
            arguments:
              path: {path_under: /workspace}
          send_report:
            requires_approval: true
            rate_limit: {per_minute: 5}
            arguments:
              to: {email_domain: example.com}
              body: {max_length: 5000}
```

Anything not listed is refused. The schema is
[`internal/policy/policy.schema.json`](internal/policy/policy.schema.json).

### Useful flags

| Flag | Meaning |
|---|---|
| `-upstream name=url` | An MCP server over HTTP, served at `/{name}/mcp` |
| `-upstream-stdio name=command` | A stdio MCP server, started by the gateway |
| `-policy file` | The policy (required, unless `-insecure-allow-all`) |
| `-scan rules\|judge\|rules+judge\|off` | Tool-result scanning; default `rules` |
| `-admin-listen addr`, `-approver name=sha256` | The approval page and who may use it |
| `-audit-db file` | The audit log; `mcpguard audit export\|verify -db file` reads it |
| `-metrics-listen addr` | Prometheus metrics at `/metrics` |

## Running the evaluations

```bash
go run ./evals/scenarios
```

AgentDojo, with your own model (Gemini, a local Ollama model, Claude, or any OpenAI-compatible server), is
described in [`evals/README.md`](evals/README.md). Nothing is hosted and no key is bundled: whoever runs it
supplies their own, through the provider's usual environment variable.

## Design decisions

- [ADR 1: Default deny](docs/adr/0001-default-deny.md)
- [ADR 2: Rules or an LLM judge](docs/adr/0002-rules-vs-llm-judge.md)
- [ADR 3: Where a gateway cannot help](docs/adr/0003-where-a-gateway-cannot-help.md)

## Status and limits

- Built with heavy AI assistance, including the argument matcher that the project brief had set aside to be
  written by hand. Read `internal/policy/argmatch.go` and its tests before relying on it.
- The LLM judge has never been run against the real API; its accuracy and cost are unknown.
- The Docker image is built and started in CI. The compose demo has only been run as the same processes
  outside Docker, and the Helm chart passes `helm lint` and renders but has not been installed on a cluster.
- SQLite only for the audit log; rate limits, tool pins and pending approvals are in memory, per process.
- Not compared against any other gateway.
