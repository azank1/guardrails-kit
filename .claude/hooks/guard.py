#!/usr/bin/env python3
"""Claude Code guardrail hooks: one script, three modes.

  guard.py bash    PreToolUse on Bash: block destructive commands, force pushes,
                   pushes to main/master, pipe-to-shell installs and reads of
                   credential stores.
  guard.py write   PreToolUse on Write/Edit/MultiEdit: block writes to protected
                   paths and content that looks like a secret.
  guard.py audit   PostToolUse on everything: append a redacted line to
                   .claude/audit/agent-audit.jsonl.

Claude Code sends the hook event as JSON on stdin. Exit 2 blocks the tool call
and shows stderr to the agent. The guards fail closed: input they cannot parse
is blocked, not waved through. The audit mode never blocks.
"""
import datetime
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

PROTECTED_BRANCHES = {"main", "master"}
WRAPPERS = {"sudo", "doas", "env", "command", "nice", "nohup", "time", "exec", "builtin", "xargs"}
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "python", "python3", "perl", "ruby", "node"}
CREDENTIAL_PATHS = [
    ".ssh/id_", ".aws/credentials", ".config/gh/hosts.yml", ".git-credentials", ".npmrc", ".pypirc",
    ".docker/config.json", ".kube/config", ".config/solana/id.json", ".ethereum/keystore",
    ".foundry/keystores", ".bitcoin/wallets", ".electrum/wallets",
]
PROTECTED_WRITE_GLOBS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*.keystore",
    ".github/workflows/*", ".claude/settings.json", ".claude/hooks/*",
]
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Anthropic/OpenAI-style key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
]


def block(reason):
    sys.stderr.write(f"Blocked by guardrails: {reason}. If this is intended, a human must run it.\n")
    sys.exit(2)


def read_event():
    try:
        event = json.loads(sys.stdin.read() or "")
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        return event
    except ValueError as e:
        block(f"could not parse the hook input ({e})")


def segments(command):
    """Split a shell command line into simple commands on ; && || | and newlines."""
    parts = re.split(r"\|\||&&|;|\||\n", command)
    out = []
    for part in parts:
        try:
            words = shlex.split(part, comments=True)
        except ValueError:
            block("could not parse the command (unbalanced quotes)")
        while words and (os.path.basename(words[0]) in WRAPPERS or re.match(r"^\w+=", words[0])):
            wrapper = os.path.basename(words[0])
            words = words[1:]
            while words and words[0].startswith("-"):
                takes_value = wrapper in ("sudo", "doas") and words[0] in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U")
                words = words[2:] if takes_value else words[1:]
        if words:
            words[0] = os.path.basename(words[0])
            out.append(words)
    return out


def current_branch(cwd):
    try:
        r = subprocess.run(["git", "-C", cwd or ".", "symbolic-ref", "--short", "-q", "HEAD"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def dangerous_rm_target(t):
    if t in ("/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "${HOME}", ".", "./", "..", "../", "*", "./*"):
        return True
    if t.startswith("/") and len([p for p in t.split("/") if p]) <= 2:
        return True
    return False


def check_bash(event):
    command = (event.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        block("Bash call without a command string")
    if re.search(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b", command):
        block("piping a download straight into a shell")
    lowered = command.replace("$HOME", "~").replace("${HOME}", "~")
    for cred in CREDENTIAL_PATHS:
        if cred in lowered:
            block(f"command touches a credential store ({cred})")
    for words in segments(command):
        prog, args = words[0], words[1:]
        if prog == "rm":
            flags = "".join(a for a in args if a.startswith("-") and not a.startswith("--"))
            recursive = "r" in flags.lower() or "--recursive" in args
            if recursive and any(dangerous_rm_target(a) for a in args if not a.startswith("-")):
                block("recursive rm on a top-level, home or wildcard path")
        if prog == "git":
            while args and args[0].startswith("-"):
                args = args[2:] if args[0] in ("-C", "-c") else args[1:]
        if prog == "git" and args:
            sub = args[0]
            rest = args[1:]
            if sub == "push":
                if any(a in ("-f", "--force", "--force-with-lease", "--mirror", "--delete", "-d") or a.startswith("--force") for a in rest):
                    block("force, mirror or delete push")
                refs = [a for a in rest if not a.startswith("-")]
                if any(r.startswith("+") for r in refs):
                    block("force push via +refspec")
                targets = {r.split(":")[-1].removeprefix("refs/heads/") for r in refs[1:]}
                if targets & PROTECTED_BRANCHES:
                    block("push to a protected branch (main/master)")
                if (len(refs) <= 1 or "HEAD" in targets) and current_branch(event.get("cwd")) in PROTECTED_BRANCHES:
                    block("push while on a protected branch (main/master)")
            if sub == "reset" and "--hard" in rest:
                block("git reset --hard discards work")
            if sub == "clean" and any(a.startswith("-") and "f" in a for a in rest):
                block("git clean -f deletes untracked files")
            if sub == "branch" and any(a in ("-D", "--delete") for a in rest) and set(rest) & PROTECTED_BRANCHES:
                block("deleting a protected branch")
        if prog in SHELLS and any(a == "-c" for a in args):
            inner = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
            if inner:
                check_bash({"tool_input": {"command": inner}, "cwd": event.get("cwd")})


def secret_in(text):
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text or ""):
            return name
    return None


def check_write(event):
    ti = event.get("tool_input")
    if not isinstance(ti, dict):
        block("write call without tool_input")
    path = ti.get("file_path") or ti.get("path") or ""
    rel = os.path.relpath(path, event.get("cwd") or os.getcwd()) if os.path.isabs(path) else path
    for g in PROTECTED_WRITE_GLOBS:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(path), g):
            block(f"{rel} is a protected path ({g})")
    texts = [ti.get("content"), ti.get("new_string")]
    texts += [e.get("new_string") for e in ti.get("edits") or [] if isinstance(e, dict)]
    for t in texts:
        name = secret_in(t if isinstance(t, str) else "")
        if name:
            block(f"content looks like a secret ({name})")


def redact(text):
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def audit(event):
    try:
        root = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
        d = os.path.join(root, ".claude", "audit")
        os.makedirs(d, exist_ok=True)
        ti = event.get("tool_input") or {}
        summary = ti.get("command") or ti.get("file_path") or ti.get("url") or ""
        line = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "session": event.get("session_id"),
            "tool": event.get("tool_name"),
            "summary": redact(str(summary))[:300],
        }
        with open(os.path.join(d, "agent-audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except Exception:
        pass  # the audit log must never block or break a tool call


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "audit":
        try:
            audit(json.loads(sys.stdin.read() or "{}"))
        except ValueError:
            pass
        return
    event = read_event()
    if mode == "bash":
        check_bash(event)
    elif mode == "write":
        check_write(event)
    else:
        block(f"unknown guard mode {mode!r}")


if __name__ == "__main__":
    main()
