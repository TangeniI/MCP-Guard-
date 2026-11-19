# Security

MCP Guard is a security tool, so reports of ways around it are welcome.

## Reporting

Please open a private report through GitHub: **Security** tab, then **Report a vulnerability**. If that is not
available to you, open an issue that says only that you have a report, and you will be contacted.

Please include the gateway configuration (policy and flags), what you sent, and what reached the MCP server or
the agent.

## What counts

- A tool call or argument that the policy should refuse but that reaches the MCP server.
- A way for an agent to approve its own call, or to reach the approval page.
- A message the gateway parses differently from the MCP server behind it.
- A way to alter or drop audit records without `mcpguard audit verify` noticing.

## What is already known

Prompt injections that are reworded, translated or encoded pass the rules scanner. That and the other known
gaps are listed in [docs/what-still-gets-through.md](docs/what-still-gets-through.md). New examples are still
useful as scenarios; see [evals/README.md](evals/README.md).
