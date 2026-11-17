"""What belongs to the model and what belongs to the harness.

Claude Code splits instructions in two (best practices, "Deterministic and
non-deterministic instructions"): a skill is read by the model, which usually
follows it; a hook, a deny rule or the sandbox is applied by Claude Code every
time. These checks find skill text that asks the model for a guarantee only
the harness can give, emphasis written for older models, and hooks that look
like they block but do not.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .files import location_for, normalize_tool_collection, read_text
from .model import Finding, add_finding
from .patterns import (
    BARE_NEVER_RE,
    BLOCKING_HOOK_EVENTS,
    BLOCKING_SIGNAL_RE,
    EMPHASIS_RE,
    EXIT_ONE_RE,
    HARD_RULE_TOKENS,
    HOOK_SCRIPT_RE,
    NEGATION_RE,
    NEVER_REASON_RE,
    PROHIBITION_RE,
    SIDE_EFFECT_COMMAND_RE,
)

RULE_EMPHASIS = "§12 Model fit"
RULE_HARNESS = "§15a Model and harness"


def prose_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges that are code, not instructions: fences and inline spans."""
    spans = [m.span() for m in re.finditer(r"^```.*?^```", text, re.M | re.S)]
    spans += [m.span() for m in re.finditer(r"`[^`\n]+`", text)]
    return spans


def in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def body_start(text: str) -> int:
    """Offset after the frontmatter: prohibitions are read in the body only."""
    match = re.match(r"---\n.*?\n---\n", text, re.S)
    return match.end() if match else 0


def check_emphasis(path: Path, text: str, profile: str, profile_source: str,
                   findings: list[Finding]) -> None:
    """One finding per file for all-caps emphasis, with the count and first lines."""
    if profile == "generic":
        return
    code = prose_spans(text)
    start = body_start(text)
    hits = [m for m in EMPHASIS_RE.finditer(text) if m.start() >= start and not in_spans(m.start(), code)]
    if not hits:
        return
    lines = sorted({text.count("\n", 0, m.start()) + 1 for m in hits})
    words = sorted({" ".join(m.group(0).split()) for m in hits})
    add_finding(
        findings, "Minor", "Defect", "All-caps emphasis written for older models",
        f"{path}:{lines[0]}",
        f"{len(hits)} marker(s) ({', '.join(words)}) on lines {', '.join(map(str, lines[:8]))}"
        f"{' …' if len(lines) > 8 else ''}; profile resolved from {profile_source}",
        "Current models follow a plainly worded line; emphasis makes them over-apply the rule "
        "(Claude Code best practices, 'What you can stop doing').",
        "Write the rule in normal case with its reason. A rule that can have no exception "
        "belongs in a hook or a deny rule, not in capitals.",
        RULE_EMPHASIS,
    )


def sentence_after(text: str, match: re.Match) -> str:
    """The rest of the sentence, across wrapped lines: the reason is often on the next one."""
    tail = text[match.start("rest"):match.start("rest") + 400]
    end = re.search(r"[.!?](?:\s|$)|\n\s*\n|\n\s*(?:[-*]|\d+\.)\s", tail)
    return tail[: end.end() if end else len(tail)]


def check_bare_never(path: Path, text: str, profile: str, findings: list[Finding]) -> None:
    """Fable 5.2 reads 'never' as absolute: ask for scope and reason."""
    if profile == "generic":
        return
    code = prose_spans(text)
    bare = [m for m in BARE_NEVER_RE.finditer(text)
            if m.start() >= body_start(text) and not in_spans(m.start(), code)
            and not NEVER_REASON_RE.search(sentence_after(text, m))]
    if not bare:
        return
    first = bare[0].group(0).strip()
    add_finding(
        findings, "Nit", "Suggestion", "Absolute 'never' without scope or reason",
        location_for(path, text, first), f"{len(bare)} line(s); first: {first!r}",
        "Fable 5.2 treats an instruction containing 'never' as absolute and may hold routine "
        "work; a bare rule also does not generalise to the cases it was written for.",
        "Add the reason and the exception ('Do not run the target's scripts: they run with your "
        "permissions'), or turn it into an approval rule ('ask before deleting files').",
        RULE_HARNESS,
    )


def hard_backing(frontmatter: dict[str, Any], plugin_hooks: bool) -> tuple[str, bool]:
    denied = " ".join(normalize_tool_collection(frontmatter.get("disallowed-tools")))
    hooked = bool(frontmatter.get("hooks")) or plugin_hooks
    return denied, hooked


def check_prose_hard_rules(skill_md: Path, text: str, frontmatter: dict[str, Any],
                           plugin_hooks: bool, findings: list[Finding]) -> None:
    """An irreversible prohibition that exists only as prose.

    The test from the talk: if Claude gets this wrong once, can you take it
    back? If not, the skill text is the wrong place for the only copy of the
    rule. Backing counts when `disallowed-tools` names the matching tool, when
    the skill or its plugin declares hooks, or (for outbound actions) when the
    skill cannot start on the model's own judgment.
    """
    denied, hooked = hard_backing(frontmatter, plugin_hooks)
    manual_only = frontmatter.get("disable-model-invocation") is True
    code = prose_spans(text)
    reported: set[str] = set()
    for match in PROHIBITION_RE.finditer(text, body_start(text)):
        line_start = text.rfind("\n", 0, match.start()) + 1
        # A table row describes a check ("errors don't leak secrets"); it is
        # not an instruction to the model.
        if in_spans(match.start("target"), code) or text[line_start:].lstrip().startswith("|"):
            continue
        target = match.group("target")
        category = next((name for name, (pattern, _) in HARD_RULE_TOKENS.items()
                         if re.search(pattern, target, re.I)), None)
        if category is None or category in reported:
            continue
        tokens = HARD_RULE_TOKENS[category][1]
        backed = hooked or any(token.lower() in denied.lower() for token in tokens) or (
            category == "outbound" and manual_only)
        if backed:
            continue
        reported.add(category)
        sentence = match.group(0).strip()
        add_finding(
            findings, "Minor", "Concern", "Irreversible prohibition exists only as prose",
            location_for(skill_md, text, sentence[:40]), sentence,
            "The model follows this almost every time, not every time; the action cannot be "
            "undone if it slips once. Auto mode blocks most dangerous commands, not all.",
            "Keep the line for its reason, and enforce it: a `disallowed-tools` entry for this "
            "skill, a PreToolUse hook that exits 2, or a deny rule in the project's "
            "settings.json (with the sandbox for scripts that could reach the same file).",
            RULE_HARNESS, confidence="Inferred",
        )


def check_side_effect_invocation(skill_md: Path, text: str, frontmatter: dict[str, Any],
                                 findings: list[Finding]) -> None:
    """A skill that pushes, publishes or deploys should start only when a person asks."""
    if frontmatter.get("disable-model-invocation") is True:
        return
    for line in text[body_start(text):].splitlines():
        command = SIDE_EFFECT_COMMAND_RE.search(line)
        if command and not NEGATION_RE.search(line[: command.start()]):
            add_finding(
                findings, "Minor", "Concern", "Side-effect workflow can start on the model's judgment",
                location_for(skill_md, text, line.strip()[:40]), line.strip(),
                f"`{command.group(0)}` reaches outside the working copy; without "
                "`disable-model-invocation: true` Claude may load this skill on its own.",
                "Add `disable-model-invocation: true` so it runs only when invoked by name, or say "
                "in the description why automatic invocation is intended.",
                RULE_HARNESS,
            )
            return


def hook_entries(hooks: Any) -> list[tuple[str, dict[str, Any]]]:
    """(event, handler) for every handler in a hooks mapping."""
    entries = []
    if not isinstance(hooks, dict):
        return entries
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            for handler in (group or {}).get("hooks", []) if isinstance(group, dict) else []:
                if isinstance(handler, dict):
                    entries.append((str(event), handler))
    return entries


def resolve_hook_script(command: str, roots: list[Path]) -> Path | None:
    for raw in HOOK_SCRIPT_RE.findall(command):
        relative = re.sub(r"^\"?\$\{?CLAUDE_[A-Z_]+\}?\"?/?", "", raw).lstrip("./")
        for root in roots:
            candidate = root / relative
            if candidate.is_file():
                return candidate
    return None


def check_hook_handlers(source: Path, source_text: str, hooks: Any, roots: list[Path],
                        findings: list[Finding]) -> None:
    """Hooks on blocking events must be able to block: exit 2 or a JSON decision."""
    for event, handler in hook_entries(hooks):
        if event not in BLOCKING_HOOK_EVENTS:
            continue
        kind = handler.get("type", "command")
        command = " ".join([str(handler.get("command", ""))] + [str(a) for a in handler.get("args", []) or []])
        if kind in ("prompt", "agent"):
            add_finding(
                findings, "Nit", "Suggestion", f"{event} hook is decided by a model",
                location_for(source, source_text, f"type: {kind}" if "type:" in source_text else kind),
                f"type={kind}",
                "A prompt or agent hook asks another model to decide; it is not deterministic.",
                "Use a command or http hook for a rule with no exceptions.",
                RULE_HARNESS,
            )
            continue
        if kind != "command":
            continue
        script = resolve_hook_script(command, roots)
        body = read_text(script) if script else None
        checked = f"{command}\n{body or ''}"
        if EXIT_ONE_RE.search(checked) and not BLOCKING_SIGNAL_RE.search(checked):
            add_finding(
                findings, "Major", "Defect", f"{event} hook fails with exit 1, which does not block",
                location_for(source, source_text, event), str(script or command),
                "Claude Code treats exit 1 as a non-blocking error: the tool call runs, or the "
                "task is marked done anyway.",
                "Exit 2 (stderr becomes the reason Claude sees), or print a JSON decision and exit 0. "
                "Add `onFailure: \"block\"` if a crash of the hook should also stop the action.",
                RULE_HARNESS,
            )


def plugin_hook_file(plugin: Path | None) -> tuple[Path | None, Any]:
    if plugin is None:
        return None, None
    path = plugin / "hooks" / "hooks.json"
    try:
        return path, json.loads(path.read_text(encoding="utf-8")).get("hooks")
    except (OSError, ValueError, AttributeError):
        return None, None


def has_pre_tool_hook(hooks: Any) -> bool:
    return any(event == "PreToolUse" for event, _ in hook_entries(hooks))
