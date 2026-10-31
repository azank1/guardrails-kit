# guardrails-kit

Fail-closed Claude Code guardrails for a team repo: one stdlib Python script, three hook modes.

| hook | blocks |
|---|---|
| `PreToolUse` Bash | recursive `rm` on `/`, `~`, `.`, `*` or top-level paths (also via `/bin/rm`, `sudo -u`, `env`, `bash -c`); force, mirror and delete pushes; pushes to `main`/`master` (also bare `git push` while on them, even before the first commit); `git reset --hard`, `git clean -f`; `curl … \| sh`; any command touching SSH keys, cloud/GitHub/npm/PyPI credentials or crypto wallets |
| `PreToolUse` Write/Edit/MultiEdit | writes to `.env*`, keys, `.github/workflows/*`, and the guard's own settings and hooks; content that looks like an AWS, GitHub, Anthropic/OpenAI, Slack or Stripe key or a private key block |
| `PostToolUse` * | never blocks; appends a redacted line per tool call to `.claude/audit/agent-audit.jsonl` |

Input it cannot parse is blocked, not waved through. Deny rules in `settings.json` cover direct reads of the same secret stores.

Install: copy `.claude/hooks/guard.py` and merge `.claude/settings.json` into the client repo, commit both so changes go through review, and add `.claude/audit/` to `.gitignore`.

Tests: `python3 test_guard.py` (stdlib only).
