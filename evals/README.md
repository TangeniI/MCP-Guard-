# Evaluations

Every number about MCP Guard comes from a file in [`results/`](results/). Tables here are pasted from
`agentdojo/summarize.py`, not typed.

## AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (arXiv 2406.13352) is a benchmark of prompt-injection
attacks on tool-using agents: 97 user tasks and 949 user-task/injection-task pairs across four suites
(workspace, travel, banking, slack) in benchmark version v1.2.2.

### How the benchmark is wired to the gateway

AgentDojo's tools are Python functions. [`agentdojo/bridge.py`](agentdojo/bridge.py) puts the gateway in the
path of every call:

```
AgentDojo agent -> GatewayToolsExecutor -> MCP Guard -> bridge MCP server -> AgentDojo tool function
```

The agent only ever sees what the gateway returns. Scoring is AgentDojo's own, unchanged.

The bridge server is a small test fixture that speaks the part of MCP Streamable HTTP that tool calls need
(JSON responses, no streaming). It is not the official MCP SDK.

### Results so far

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

Attack: AgentDojo's `important_instructions`. Gateway commit and exact flags are recorded in each file.

Two kinds of row:

- **"none (scripted)"** uses an agent with no model. It replays each task's ground-truth tool calls and
  ignores what the tools return, so it cannot be fooled and says nothing about whether attacks succeed. It
  was run to check the wiring and to measure what the gateway does to tool traffic, at no model cost.
- **Rows naming a model** are real agent runs. Those marked *partial* cover a slice of one suite, run on a
  free tier; they are pilots, not a benchmark score. The full benchmark with a capable model has not been run.

### What the scripted runs do and do not show

They show:

- **The wiring is sound.** With the guard off, all 97 tasks and 949 pairs score as AgentDojo expects through
  the gateway and bridge.
- **The rules scanner quarantined every tool result that carried this attack** (1,234 of 1,234) and none of the
  339 benign results or the 1,597 clean results returned during attack runs.
- **Overhead inside the gateway is small**: a median of about 0.2 ms per call with rules scanning, worst-suite
  p95 under 6 ms (workspace, which has the largest results). This is time inside the gateway; it excludes the
  extra network hop and the audit write, which happens after the response is sent.

They do not show:

- **Attack success rate, with or without the gateway.** That needs a model as the agent.
- **That the scanner generalises.** `important_instructions` is one fixed, public template, and a single rule
  (`task-hijack`) matched all of it. The rules were written by someone who knew the general shape of such
  attacks. On the project's own held-out samples (`internal/scan/testdata/heldout.jsonl`), which use varied
  wording, the same rules caught 3 of 22 injections and wrongly flagged 3 of 22 clean samples. Expect the real
  figure for a rephrased attack to be far below 100%.
- **The utility cost of quarantining.** A quarantined result is withheld whole. A real agent that needed the
  rest of that result (the calendar events around the injected one, say) loses it; the scripted agent does not
  read results, so it cannot show this. "Utility under attack: 100%" above is therefore not meaningful.
- **What the policy layer does.** The suite allow-list permits every tool the attacker wants, and the per-task
  policy is an oracle (it is derived from the ground-truth solution). A realistic static policy with argument
  rules (for example, payments only to known recipients) has not been written for AgentDojo. The policy
  layer's effect is measured in the MCP scenario suite instead.

### Reproducing

```bash
python3 -m venv evals/agentdojo/.venv
```

```bash
evals/agentdojo/.venv/bin/pip install -r evals/agentdojo/requirements.txt
```

```bash
evals/agentdojo/.venv/bin/python evals/agentdojo/run.py --agent ground-truth --guard scan
```

```bash
evals/agentdojo/.venv/bin/python evals/agentdojo/summarize.py
```

### Running with a model (bring your own)

Nothing here is hosted and no model or key is bundled. Whoever runs the benchmark chooses the model and, for
hosted ones, pays that provider from their own account. Keys are read by each provider's SDK from its usual
environment variable; the runner never reads, prints or stores them, and `scripts/check-secrets.sh` (run in CI)
fails the build if anything key-shaped is committed.

| Provider | Flag | Needs | Cost |
|---|---|---|---|
| Google Gemini (AI Studio) | `--provider google` | `GEMINI_API_KEY` | Free tier on some models, with request limits shown per project in AI Studio |
| Ollama (local) | `--provider ollama` | Ollama running locally with a tool-capable model pulled | Free; slow on a laptop |
| Anthropic Claude | `--provider anthropic` | `ANTHROPIC_API_KEY` | Billed per token to that API account |
| OpenAI, or any OpenAI-compatible server | `--provider openai` (`--base-url` for others) | `OPENAI_API_KEY` | Billed by that provider |

A small pilot on one suite:

```bash
evals/agentdojo/.venv/bin/python evals/agentdojo/run.py --agent llm --provider google --model gemini-3.6-flash --guard off --suites banking --rpm 10
```

Run once with `--guard off` and once with each guard configuration, using the same model, attack and date.

Free tiers and small quotas are handled three ways: `--rpm` caps requests per minute, rate-limit errors are
retried with a growing wait, and if the provider keeps refusing the run stops cleanly and prints a
`--resume` command that continues from the last finished task without repeating work.

Files under [`results/smoke/`](results/smoke/) are tiny runs used to check that a provider path works. They
are too small to draw conclusions from and are not part of the results table.

## MCP-specific scenarios

[`scenarios/`](scenarios/) holds 82 small stories played against the real gateway code with a scripted MCP
server: reads and writes outside allowed paths, exfiltration through arguments, tools never granted, poisoned
tool descriptions, tool definitions that change after first sight, prompt injection in tool results, and
benign tasks that must keep working. No model is involved: an attack scenario asks whether the harmful thing
was possible at all.

```bash
go run ./evals/scenarios
```

Each scenario runs in four gateway configurations (off, policy only, content only, both), so the results
file shows which layer does the work, and lists every miss with both layers on.

**The held-out rule.** 45 scenarios are marked `heldout`. Rules and code must never be changed to fix a
held-out miss. To work on one, move it to `dev` in `scenarios/generate.py` and write a new held-out scenario
to replace it. `go test ./evals/scenarios` fails if a dev scenario regresses and only reports held-out misses.

All scenarios share one policy, [`scenarios/policy.yaml`](scenarios/policy.yaml), written for a plausible
office assistant. No scenario gets a policy tailored to it.

Both the scenarios and the policy were written by the same author as the gateway. That is a weaker test than
scenarios from someone trying to break it.
