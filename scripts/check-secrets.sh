#!/usr/bin/env bash
# Fails if anything that looks like a real credential is tracked by git.
# Run locally before committing; CI runs it on every push.
#
# Deliberately fake values used by tests and examples (for instance
# "test-key-not-real", "demo-token-not-a-secret") do not match these shapes.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Shapes of real keys: Anthropic, OpenAI, Google AI Studio (old and new), AWS, GitHub,
# and PEM private keys.
pattern='sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'

status=0
if git ls-files -z | xargs -0 grep -nIE "$pattern" -- 2>/dev/null; then
  echo "error: the lines above look like real credentials. Remove them and rotate the key." >&2
  status=1
fi
# Environment files hold keys by design and must never be tracked.
if git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$'; then
  echo "error: the .env files above are tracked by git." >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "no credentials found in tracked files"
exit "$status"
