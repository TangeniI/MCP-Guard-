# ADR 2: Rules or an LLM judge for scanning tool results

Status: accepted, with the judge unmeasured.

## Decision

Pattern rules run by default. An LLM judge is optional (`-scan judge` or `-scan rules+judge`) and is consulted
only when the rules find nothing. The judge is fail-closed: only a well-formed "safe" answer lets a result
through; "unsure", an error, a timeout, a refusal or an unreadable answer all quarantine it.

## The trade

| | Rules | LLM judge |
|---|---|---|
| Added time per call | About 0.2 ms median, under 6 ms at worst-suite p95 (AgentDojo scripted runs) | One model call per tool result; not measured |
| Cost | None | Per token, on every tool result the rules pass; not measured |
| Predictable | Yes: same input, same answer, and the match is in the audit log | No |
| Catches rephrasing | No | Expected to, but not measured |
| Attack surface | Small | The judge reads attacker text and can itself be targeted |

## What the rules actually catch

All figures are from files in `evals/results/` or printed by the named test.

- **One fixed public template:** 1,234 of 1,234 injected tool results in AgentDojo's `important_instructions`
  attack, with 0 of 339 benign results flagged (`agentdojo-20261111-172405-ground-truth-guard-scan.json`).
  One rule matched all of them, and the rules were written by someone who knew what such attacks look like.
- **Varied wording, held out:** 3 of 22 injections, and 3 of 22 clean samples wrongly flagged
  (`TestRulesHeldOutSet`, `internal/scan/testdata/heldout.jsonl`).
- **MCP scenarios, held out:** 0 of 8 injected results and 0 of 5 poisoned tool descriptions, and 2 of 13
  benign scenarios wrongly quarantined (`scenarios-20261112-125453.json`).

So the rules are a cheap filter for known shapes of attack. They are not a defence against an attacker who
rewords.

## What is not known

The judge has only been run against a fake API in tests. Its accuracy, latency and cost are unmeasured, so
this ADR does not claim it closes the gap above. Until it is measured on the held-out sets, treat scanning as
"rules only".

## Safeguards on the judge

- The tool output is passed as data between markers containing a random value the attacker cannot predict,
  and never placed in the system prompt.
- The answer must match a JSON schema and is parsed strictly; anything else is an error.
- Results larger than the judge's limit are not truncated (the unread part could hold the attack); they are
  quarantined.

## Open question

Quarantine withholds the whole tool result. In a six-task local-model smoke test this stopped every attack
and also failed every user task under attack, because the legitimate data sat next to the injection. Cutting
out only the flagged passage would keep more tasks working but trusts the scanner to find the attack's edges.
Not built; it should be measured before it is offered.
