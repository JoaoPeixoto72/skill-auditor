#!/usr/bin/env python3
"""PreToolUse guard for external links: whose link is this, and did it change?

Runs before every WebFetch and every Bash command that reaches the network
(curl, wget, Invoke-WebRequest, ...). For each URL it:

1. finds which installed skills declare it (`external-resources.json`) or
   mention it in their files — project, user and plugin skills;
2. finds the skill active in the current turn, from the transcript (the last
   `Skill` call or "Base directory for this skill:" since the user's prompt);
3. decides:
   - Tier 1 (immutable, `sha256-…`): downloads it and compares the hash
     before the tool runs — changed content is denied, naming the skill;
   - Tier 0 (documentation, "never fetched"): a skill fetching it at runtime
     is asked about; a person reading it is not;
   - a link a skill uses without declaring it: denied when that skill is
     active, asked about otherwise;
   - a link no skill knows, fetched while a skill is active: asked about;
   - anything else: left to the normal permission flow.

Allow is never printed: the guard only ever narrows what Claude Code already
permits. What it cannot see: network calls made inside a script a skill runs
(`python fetch.py`) — the static audit covers those.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

NETWORK_COMMAND_RE = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b", re.I)
URL_RE = re.compile(r"https?://[^\s\"'`<>)|]+", re.I)
TEXT_SUFFIXES = {".md", ".json", ".yaml", ".yml", ".py", ".sh", ".ps1", ".js", ".mjs", ".ts", ".txt"}
SKIP_DIRS = {".git", "node_modules", "tests", "fixtures", "__pycache__", ".venv"}
MAX_FILE_BYTES = 512 * 1024
TRANSCRIPT_TAIL_BYTES = 2 * 1024 * 1024
FETCH_TIMEOUT = 15
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
BASE_DIRECTORY_RE = re.compile(r"Base directory for this skill:\s*(\S+)")
SEVERITY = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Owner:
    skill: str
    where: str
    declared: bool
    tier: int | None = None
    hash: str | None = None
    max_bytes: int | None = None


# ------------------------------------------------------------ the event

def urls_in(event: dict) -> list[str]:
    tool, given = event.get("tool_name"), event.get("tool_input") or {}
    if tool == "WebFetch":
        return [given.get("url", "")] if given.get("url") else []
    command = given.get("command", "") if tool == "Bash" else ""
    return URL_RE.findall(command) if NETWORK_COMMAND_RE.search(command) else []


def canonical(url: str) -> str:
    return url.rstrip(".,;:").rstrip("/")


# ------------------------------------------------------------ installed skills

def latest_versions(cache: Path) -> list[Path]:
    """<cache>/<marketplace>/<plugin>/<version>: the newest version of each plugin."""
    newest = []
    for plugin in (p for m in cache.iterdir() if m.is_dir() for p in m.iterdir() if p.is_dir()):
        versions = [v for v in plugin.iterdir() if v.is_dir()]
        if versions:
            newest.append(max(versions, key=lambda v: v.stat().st_mtime))
    return newest


def skill_dirs(cwd: Path, home: Path) -> list[Path]:
    roots = [cwd / ".claude" / "skills", cwd / ".agents" / "skills", home / ".claude" / "skills"]
    cache = home / ".claude" / "plugins" / "cache"
    if cache.is_dir():
        roots += [version / "skills" for version in latest_versions(cache)]
    return [d for root in roots if root.is_dir() for d in root.iterdir() if (d / "SKILL.md").is_file()]


def declared_resources(skill: Path) -> list[tuple[str, Owner]]:
    try:
        manifest = json.loads((skill / "external-resources.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [(canonical(item["url"]),
             Owner(skill.name, str(skill / "external-resources.json"), True, item.get("tier"),
                   item.get("hash"), item.get("maxBytes")))
            for item in manifest.get("resources", []) if isinstance(item, dict) and item.get("url")]


def mentioned_urls(skill: Path) -> dict[str, str]:
    """URL -> first file of the skill that mentions it."""
    found: dict[str, str] = {}
    for path in skill.rglob("*"):
        if path.suffix not in TEXT_SUFFIXES or SKIP_DIRS & set(path.relative_to(skill).parts):
            continue
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        for url in URL_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            found.setdefault(canonical(url), str(path))
    return found


def build_index(skills: list[Path]) -> dict[str, list[Owner]]:
    index: dict[str, list[Owner]] = {}
    for skill in skills:
        declared = declared_resources(skill)
        for url, owner in declared:
            index.setdefault(url, []).append(owner)
        known = {url for url, _ in declared}
        for url, where in mentioned_urls(skill).items():
            if url not in known:
                index.setdefault(url, []).append(Owner(skill.name, where, False))
    return index


# ------------------------------------------------------------ the active skill

def turn_records(transcript: Path) -> list[dict]:
    """Transcript records since the user's last prompt, newest last."""
    with transcript.open("rb") as handle:
        handle.seek(max(0, transcript.stat().st_size - TRANSCRIPT_TAIL_BYTES))
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    records = []
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        records.append(record)
        if is_human_prompt(record):
            break
    return list(reversed(records))


def is_human_prompt(record: dict) -> bool:
    """A prompt the person typed; skill bodies injected as user turns are meta."""
    message = record.get("message") or {}
    if record.get("type") != "user" or record.get("isMeta") or message.get("role") != "user":
        return False
    content = message.get("content")
    return isinstance(content, str) or not any(
        isinstance(block, dict) and block.get("type") == "tool_result" for block in content or [])


def texts(message: dict) -> list[str]:
    """Every string a message carries: text blocks and tool results."""
    content = message.get("content")
    if isinstance(content, str):
        return [content]
    found = []
    for block in content or []:
        if not isinstance(block, dict):
            continue
        inner = block.get("text") if block.get("type") == "text" else block.get("content")
        if isinstance(inner, str):
            found.append(inner)
        elif isinstance(inner, list):
            found += [b.get("text", "") for b in inner if isinstance(b, dict)]
    return found


def skill_named_in(record: dict) -> str | None:
    message = record.get("message") or {}
    named = None
    for block in message.get("content") if isinstance(message.get("content"), list) else []:
        if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Skill":
            named = str((block.get("input") or {}).get("skill", "")).split(":")[-1] or named
    for text in texts(message):
        base = BASE_DIRECTORY_RE.search(text)
        command = re.search(r"<command-name>/?([\w:.-]+)</command-name>", text)
        if base:
            named = Path(base.group(1)).name
        elif command:
            named = command.group(1).split(":")[-1]
    return named


def active_skill(transcript_path: str | None) -> str | None:
    """The last skill loaded since the person's last prompt, if any."""
    if not transcript_path or not Path(transcript_path).is_file():
        return None
    active = None
    for record in turn_records(Path(transcript_path)):
        active = skill_named_in(record) or active
    return active


# ------------------------------------------------------------ deciding

def fetch_digest(url: str, max_bytes: int) -> str:
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as response:  # noqa: S310 - https only, below
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"larger than the declared {max_bytes} bytes")
    return "sha256-" + hashlib.sha256(body).hexdigest()


def check_tier1(url: str, owner: Owner) -> tuple[str, str]:
    if not url.lower().startswith("https://"):
        return "deny", f"{owner.skill} declares {url} as Tier 1, which requires https."
    try:
        actual = fetch_digest(url, owner.max_bytes or DEFAULT_MAX_BYTES)
    except (OSError, ValueError) as error:
        return "ask", f"Could not verify {url}, pinned by skill {owner.skill}: {error}."
    if actual.lower() != str(owner.hash).lower():
        return "deny", (f"Content of {url} changed since skill {owner.skill} was audited: "
                        f"declared {owner.hash}, now {actual}. Re-audit the skill before using it.")
    return "allow", ""


def decide(url: str, owners: list[Owner], active: str | None) -> tuple[str, str]:
    declared = [o for o in owners if o.declared]
    undeclared = [o for o in owners if not o.declared]
    for owner in declared:
        if owner.tier == 1 and owner.hash:
            decision = check_tier1(url, owner)
            if decision[0] != "allow":
                return decision
    if active and any(o.skill == active and o.tier == 0 for o in declared):
        return "ask", f"Skill {active} declares {url} as documentation (Tier 0, never fetched), yet fetches it."
    if active and any(o.skill == active for o in undeclared):
        where = next(o.where for o in undeclared if o.skill == active)
        return "deny", f"Skill {active} uses {url} without declaring it (found in {where})."
    if undeclared and not declared:
        names = ", ".join(sorted({o.skill for o in undeclared}))
        return "ask", f"{url} appears undeclared in skill(s) {names}."
    if active and not owners:
        return "ask", f"Skill {active} is active and {url} is declared by no installed skill."
    return "allow", ""


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError as error:
        print(f"skill-auditor link guard: unreadable hook input ({error}).", file=sys.stderr)
        return 0
    urls = [canonical(u) for u in urls_in(event)]
    if not urls:
        return 0
    index = build_index(skill_dirs(Path(event.get("cwd") or os.getcwd()), Path.home()))
    active = active_skill(event.get("transcript_path"))
    verdicts = [decide(url, index.get(url, []), active) for url in urls]
    decision, reason = max(verdicts, key=lambda v: SEVERITY[v[0]])
    if decision != "allow":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": decision,
            "permissionDecisionReason": f"skill-auditor link guard: {reason}"}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
