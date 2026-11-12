# ADR 3: Where a gateway cannot help

Status: accepted.

A gateway sees tool traffic: which tool is called, with which arguments, and what comes back. Anything that
does not pass through a tool call, or that looks legitimate at that level, is outside what it can decide.

## Outside its sight

- **The model's own reply.** If the model reads a secret through an allowed tool and then repeats it in its
  answer to the user, or to whoever is on the other end of the conversation, no tool call carries it.
- **Tools the gateway is not in front of.** Built-in tools of the agent framework, a browser, a code
  interpreter, or an MCP server the agent reaches directly are all unmediated.
- **What a server does internally.** The gateway approves `read_file("/workspace/a")`; it cannot know the
  server follows a symlink out of `/workspace`, URL-decodes `%2e%2e`, or sends a copy elsewhere.
- **The instruction the user gave.** A user who asks for something harmful through allowed tools is using
  the system as configured.

## Visible, but not decidable from the call alone

- **Harmful content to an allowed destination.** A password emailed to a colleague at the allowed domain, or
  customer data placed in the query string of an allowed API. Both are in the scenario suite as known misses
  (`arg-15`, `arg-16`).
- **A sequence of individually harmless calls.** Read a file, then post a "summary" somewhere permitted. The
  gateway decides each call on its own and keeps no memory of what earlier results contained.
- **Injections it does not recognise.** See ADR 2: rephrased, translated or encoded instructions pass the
  rules.
- **A server that is malicious from its first response.** Tool pinning is trust-on-first-use; it notices
  change, not original sin.

## What this means for a deployment

The gateway is one layer. It makes the tool surface small and audited, and it removes the cheapest attacks.
It should sit alongside: least privilege in the servers themselves, credentials scoped per server, egress
controls on the hosts that run tools, and review of the audit log. It is not a reason to give an agent access
it should not have.
