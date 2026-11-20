#!/usr/bin/env python3
"""Hawthorn guard (written by `hawthorn install-hooks`; re-run it to update, don't edit).
Claude Code PreToolUse hook: denies Bash/PowerShell commands that run `git push` or
`git commit` and names the `hawthorn` command to use instead. Every other command is
allowed. Plain commits by Combwork itself don't go through Claude's tools, so they aren't
affected. Standard library only."""
import json
import re
import sys

GIT = r"(?<![\w.-])git(?:\.exe)?(?:\s+(?:-C\s+(?:\"[^\"]*\"|'[^']*'|\S+)|-c\s+\S+|--?[A-Za-z][\w-]*(?:=\S+)?))*\s+"
PUSH = re.compile(GIT + r"push(?![\w-])", re.I)
COMMIT = re.compile(GIT + r"commit(?![\w-])", re.I)


def decide(command):
    """None to allow, else the reason for denying."""
    if PUSH.search(command):
        return ("Raw `git push` is blocked in this workspace: pushes go through Hawthorn's checks. "
                "Use: hawthorn push <repo>   (add --dry-run to check first)")
    if COMMIT.search(command):
        return ("Raw `git commit` is blocked for agents in this workspace. "
                "Use: hawthorn commit <repo> -m \"<message>\" [paths]   (stages the paths, or the tracked "
                "changes; strips Office metadata; noreply identity; runs the pre-commit checks)")
    return None


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig") or "{}")
    except ValueError:
        return 0
    if data.get("tool_name") not in ("Bash", "PowerShell"):
        return 0
    command = (data.get("tool_input") or {}).get("command") or ""
    reason = decide(command)
    if reason:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
