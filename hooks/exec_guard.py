#!/usr/bin/env python3
"""PreToolUse guard: while an auditor runs, the audited code does not.

The security and readiness auditors read untrusted skills. Their SKILL.md
says not to run the target's scripts, and that line is followed almost every
time - but running a malicious script once cannot be undone, so the rule is
also enforced here, by the harness (Claude Code best practices: "If something
has to happen every time, make it a hook").

Scope: only while one of this plugin's skills is the active skill of the
current turn (from the transcript, as in the link guard). Outside an audit the
guard says nothing, so it never gets in the way of normal work.

Blocked while an audit is active (exit 2, the reason on stderr):
- an interpreter given a file or a module: `bash x.sh`, `python x.py`,
  `python -m pkg`, `node x.js`, `source x`, `. x`, `pwsh x.ps1`, ...
- a file executed directly: `./x`, `path/to/x.sh`;
- a runner that executes the project's code: `npm test`, `npx`, `make`,
  `pytest`, `pip install`, `uv run`, `cargo run`, `go test`, ...

Allowed: this plugin's own wrappers (`skills/<auditor>/scripts/audit.sh`,
`gate.sh`), inline code the model wrote (`python -c`), and every read-only
command. A guard that crashes while an audit is active blocks; one that
crashes outside an audit lets the call through.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from link_guard import active_skill  # noqa: E402

AUDITORS = {"skill-security-auditor", "skill-readiness-auditor", "skill-release-gate"}
PLUGIN_ROOT = Path(__file__).resolve().parents[1]
OWN_WRAPPER_RE = re.compile(
    r"/skills/(?:skill-security-auditor|skill-readiness-auditor)/scripts/audit\.sh$|"
    r"/skills/skill-release-gate/scripts/gate\.sh$")

SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||;|\||\n|\$\(|`")
PREFIX_RE = re.compile(r"^(?:(?:sudo|env|nohup|time|exec|command)\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*")
INTERPRETER_RE = re.compile(
    r"^(?P<interpreter>bash|sh|zsh|dash|ksh|fish|source|\.|python[0-9.]*|py|pypy[0-9.]*|node|deno|bun|"
    r"ruby|perl|php|pwsh|powershell(?:\.exe)?|cmd(?:\.exe)?|Rscript|tsx|ts-node|osascript|cscript|wscript)"
    r"(?:\s+(?P<args>.*))?$", re.I)
RUNNER_RE = re.compile(
    r"^(?:npm\s+(?:run|test|start|install|i|ci|exec|rebuild)|npx|pnpm\s+(?:run|test|install|i|exec|dlx)|"
    r"pnpx|yarn(?:\s+(?:run|test|install|dlx))?|bunx|make|cmake|pytest|tox|nox|"
    r"pip[0-9.]*\s+install|uv\s+(?:run|pip\s+install|sync|tool\s+run)|uvx|poetry\s+(?:run|install)|"
    r"pipx\s+run|cargo\s+(?:run|test|build)|go\s+(?:run|test|generate)|bundle\s+exec|rake|"
    r"gradle|gradlew|\./gradlew|mvn|dotnet\s+(?:run|test)|deno\s+(?:run|task)|bun\s+(?:run|test|x))\b",
    re.I)
# `./x`, `../x`, or any path to a script file. A bare absolute binary
# (`/usr/bin/grep`) is a system tool, not the target's code.
DIRECT_EXEC_RE = re.compile(
    r"^(?P<path>\.{1,2}/[^\s]+|[^\s]+\.(?:sh|bash|py|js|mjs|cjs|ts|rb|pl|php|ps1|psm1|bat|cmd|exe))(?:\s|$)",
    re.I)


def normalise(path: str) -> str:
    path = path.strip("'\"").replace("\\", "/")
    drive = re.match(r"^([A-Za-z]):/", path)
    if drive:
        path = f"/{drive.group(1).lower()}/{path[3:]}"
    return path.lower()


def is_own_wrapper(path: str) -> bool:
    norm = normalise(path)
    return bool(OWN_WRAPPER_RE.search(norm)) and norm.startswith(normalise(str(PLUGIN_ROOT)))


def first_operand(args: str) -> tuple[str | None, bool]:
    """The file an interpreter would run, and whether it was `-m module`."""
    tokens = args.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-c", "-e", "--eval", "-Command", "-command", "/c", "/C"):
            return None, False  # inline code the model wrote: no target file runs
        if token == "-m":
            return (tokens[index + 1] if index + 1 < len(tokens) else "-m"), True
        if token.startswith("-"):
            index += 1
            continue
        return token, False
    return None, False


def blocked_reason(command: str) -> str | None:
    for raw in SEGMENT_SPLIT_RE.split(command):
        segment = PREFIX_RE.sub("", raw.strip())
        if not segment:
            continue
        interpreter = INTERPRETER_RE.match(segment)
        if interpreter:
            operand, module = first_operand(interpreter.group("args") or "")
            if operand is None or (not module and is_own_wrapper(operand)):
                continue
            kind = "module" if module else "file"
            return f"`{interpreter.group('interpreter')}` would run the {kind} `{operand}`"
        runner = RUNNER_RE.match(segment)
        if runner:
            return f"`{runner.group(0)}` runs the project's own code"
        direct = DIRECT_EXEC_RE.match(segment)
        if direct and not is_own_wrapper(direct.group("path")):
            return f"`{direct.group('path')}` would be executed directly"
    return None


def main() -> int:
    active = None
    try:
        event = json.loads(sys.stdin.read() or "{}")
        if event.get("tool_name") != "Bash":
            return 0
        active = active_skill(event.get("transcript_path"))
        if active not in AUDITORS:
            return 0
        reason = blocked_reason(str((event.get("tool_input") or {}).get("command", "")))
    except Exception as error:  # noqa: BLE001 - fail closed only inside an audit
        print(f"skill-auditor exec guard: could not check the command ({error}).", file=sys.stderr)
        return 2 if active in AUDITORS else 0
    if reason is None:
        return 0
    print(f"skill-auditor exec guard: {active} is auditing untrusted code and {reason}. "
          "The audit reads files; it does not run them. Use the audit wrapper, or read the "
          "file instead. If you need to run it, do it after the audit, in a sandbox.",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
