# ADR 1: Default deny

Status: accepted.

## Decision

The gateway allows nothing it has not been told to allow. An agent with no identity, a server the agent's
policy does not name, a JSON-RPC method outside a small fixed set, a tool the policy does not list, and an
argument the tool's rules do not mention are all refused. A policy that fails to parse stops the gateway from
starting. A gateway started with no policy refuses to run unless `-insecure-allow-all` is given by name.

The same rule covers everything that depends on something else working: an approval nobody answers, a judge
that times out or answers unclearly, a tool result too large to scan, and an audit log that cannot be written
all end in "no".

## Why

- The agent is the thing being constrained, and its inputs are partly written by attackers. A list of
  forbidden things has to anticipate every attack; a list of permitted things only has to describe the job.
- Failures are then visible. A missing permission shows up as a refused call with a reason in the audit log.
  A missing prohibition shows up as an incident.
- It makes the gateway's behaviour on unknown input easy to state and to test: see the golden decisions in
  `internal/policy/testdata/decisions/` and the fuzz tests.

## What it costs

- **Someone has to write and maintain the policy.** Every new tool, and every new argument on an existing
  tool that has argument rules, is refused until the policy is updated.
- **Tasks outside the policy fail.** The cost depends entirely on how well the policy matches the work.
- **Measured so far** (see `evals/results/`):
  - MCP scenario suite, policy layer only: 22 of 22 benign tasks still worked
    (`scenarios-20261112-125453.json`). The policy was written for that office assistant, so this shows the
    floor, not a typical figure.
  - AgentDojo with a scripted agent and a per-task policy derived from the answer key: 97 of 97 tasks. That
    policy is an oracle, so it shows only that a perfectly fitted policy costs nothing.
- **Not measured:** the cost of a realistic, hand-written policy on tasks its author did not foresee. That
  needs a static policy per AgentDojo suite and a model run, which has not been done.

## Consequences

- Argument rules are opt-in per tool. A tool listed as `name: {}` accepts any arguments; once it has an
  `arguments` section, unlisted arguments are refused unless `allow_other_arguments: true`.
- A denied tool call is returned to the model as a failed tool result with the reason, not as a transport
  error, so the agent can carry on with the rest of its task.
