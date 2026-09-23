"""What a description says: its verb, its activation, its boundaries, its model profile."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Sequence
from .files import plugin_root
from .model import ACTION_VERBS, VALID_MODELS
from .patterns import CLAUDE_MODEL_ID_RE, MANDATORY_ALTERNATIVE_RE, NEGATED_BEFORE_RE, READ_ONLY_RE


def description_first_word(description: str) -> str:
    match = re.match(r"\s*([^\W\d_]+)", description)

    return match.group(1).lower() if match else ""


def begins_with_action(description: str) -> bool:
    """An imperative, a third-person verb, or a Romance-language infinitive."""
    word = description_first_word(description)
    stems = {word, word[:-1], word[:-2]} if word.endswith("s") else {word}
    romance_infinitive = len(word) > 3 and word.endswith(("ar", "er", "ir"))
    return bool(stems & ACTION_VERBS) or romance_infinitive


def description_has_when_to_use(description: str) -> bool:
    # An activation condition names a moment or a trigger. The lifecycle-stage
    # list was previously closed, which rejected valid phrasings such as
    # "before signing" or "after a quarantine event".
    patterns = [
        r"\buse\s+(?:this\s+)?(?:skill\s+)?(?:when|before|after|for|during|once)\b",
        r"\bwhen\s+(?:asked|reviewing|creating|auditing|checking|the\s|a\s|an\s)",
        r"\bbefore\s+\w+",
        r"\bafter\s+\w+",
        r"\bduring\s+\w+",
        r"\bonce\s+\w+",
        r"\bprior\s+to\s+\w+",
        r"\bat\s+(?:commit|release|review|install\w*|publish\w*)\b",
        # Portuguese and Spanish: the same moments, in the author's language.
        r"\b(?:usar|use|utilizar)\s+(?:quando|antes|depois|no|na|ao|al|cuando)\b",
        r"\b(?:quando|cuando)\s+\w+",
        r"\b(?:antes|depois|despu[ée]s)\s+de\s+\w+",
        r"\bno\s+(?:in[íi]cio|princ[íi]pio|fim|final)\s+de\b",
        r"\bao\s+(?:abrir|fechar|come[çc]ar|terminar|rever)\b",
    ]

    return any(re.search(pattern, description, re.I) for pattern in patterns)


def description_has_negative_boundary(description: str) -> bool:
    patterns = [
        r"\bdo\s+not\s+use\b",
        r"\bdon't\s+use\b",
        r"\bnot\s+for\b",
        r"\binstead\s+use\b",
        r"\buse\s+.+\s+instead\b",
        r"\bn[ãa]o\s+(?:usar|use|é|e|serve)\s+para\b",
        r"\bno\s+(?:usar|use|es|sirve)\s+para\b",
    ]

    return any(re.search(pattern, description, re.I) for pattern in patterns)


def extract_mandatory_alternatives(description: str) -> set[str]:
    return {
        match.group(1).lower()
        for match in MANDATORY_ALTERNATIVE_RE.finditer(description)
    }


def sibling_skill_exists(skill_dir: Path, name: str) -> bool:
    return (skill_dir.parent / name / "SKILL.md").is_file()


def resolve_profile(
    requested_profile: str | None,
    frontmatter: dict[str, Any],
    skill_dir: Path,
) -> tuple[str, str]:
    if requested_profile:
        return requested_profile, "--model"

    declared = frontmatter.get("model")

    if isinstance(declared, str) and (
        declared in VALID_MODELS or CLAUDE_MODEL_ID_RE.match(declared)
    ):
        return "claude", f"frontmatter model: {declared}"

    if declared:
        return "generic", f"fallback from unresolved model: {declared}"

    # A skill under `.claude/` or inside a Claude Code plugin runs on Claude.
    root = plugin_root(skill_dir)
    if ".claude" in skill_dir.parts or (root is not None and (root / ".claude-plugin").is_dir()):
        return "claude", "host: Claude Code"

    return "generic", "fallback"


def claims_read_only(text: str) -> bool:
    for match in READ_ONLY_RE.finditer(text):
        before = text[max(0, match.start() - 24):match.start()]
        if not NEGATED_BEFORE_RE.search(before):
            return True
    return False
