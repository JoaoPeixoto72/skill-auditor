#!/usr/bin/env python3
"""Deterministic mechanical readiness auditor for Agent Skills.

This program is read-only. It evaluates structural readiness, local-resource
resolution, permission-command coherence, basic trigger quality, portability,
and security-handoff signals.

It does not certify security and does not execute target scripts.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

# Reports contain `·` and `§`. Redirected stdout defaults to the system locale
# on Windows, which writes cp1252 bytes that skill-release-gate cannot decode.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


VERSION = "1.0.0"

SEVERITY_WEIGHT = {
    "Blocker": 4,
    "Major": 3,
    "Minor": 2,
    "Nit": 1,
}

VALID_MODELS = {
    "opus",
    "sonnet",
    "haiku",
    "fable",
    "inherit",
}

# Claude Code also accepts a full model id (`claude-opus-5-5`).
CLAUDE_MODEL_ID_RE = re.compile(r"^claude-[a-z0-9-]+$")

VALID_EFFORTS = {
    "low",
    "medium",
    "high",
}

# One profile per family whose vendor publishes prompting guidance the audit
# can cite. `claude` follows Anthropic's current-model pages (see
# references/model-profiles.md); a family without such a source is `generic`.
VALID_PROFILES = {
    "generic",
    "claude",
}

EXCLUDED_DIRECTORIES = {
    ".git",
    ".audit",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "fixtures",
    "test-fixtures",
}

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".jsonc",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".ps1",
    ".rb",
    ".pl",
    ".php",
    ".xml",
    ".html",
}

SCRIPT_EXTENSIONS = {
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".ps1",
    ".rb",
    ".pl",
    ".php",
}

DIRECT_EXECUTION_EXTENSIONS = {
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".rb",
    ".pl",
    ".php",
}

ACTION_VERBS = {
    "aggregate",
    "analyze",
    "analyse",
    "assess",
    "audit",
    "build",
    "check",
    "classify",
    "combine",
    "compare",
    "compile",
    "compose",
    "configure",
    "convert",
    "create",
    "debug",
    "decide",
    "deploy",
    "derive",
    "detect",
    "diagnose",
    "document",
    "enforce",
    "evaluate",
    "explain",
    "extract",
    "find",
    "format",
    "gate",
    "generate",
    "identify",
    "implement",
    "inspect",
    "install",
    "lint",
    "locate",
    "map",
    "measure",
    "merge",
    "migrate",
    "monitor",
    "optimize",
    "optimise",
    "plan",
    "prepare",
    "process",
    "profile",
    "rank",
    "refactor",
    "render",
    "report",
    "resolve",
    "review",
    "run",
    "scan",
    "score",
    "search",
    "select",
    "simplify",
    "sort",
    "summarize",
    "summarise",
    "test",
    "trace",
    "track",
    "transform",
    "translate",
    "update",
    "upgrade",
    "validate",
    "verify",
    "write",
}

# A reference starts a path: `scripts/x.py`, or a sibling skill's file as
# `../other-skill/scripts/x.py`. Preceded by `/` it is the tail of a longer
# path (`<plugin>/skills/a/scripts/x.py`) and is not this skill's resource.
RESOURCE_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_./<>-])"
    r"((?:\.\./[A-Za-z0-9_.-]+/)?"
    r"(?:references|scripts|assets|templates|schemas|baselines)/"
    r"[A-Za-z0-9_./*?{}\[\]-]+)"
)

# `<plugin>/scripts/x.py` names a resource shipped at the plugin root, shared
# by every skill of the plugin: the declared shared-resource root of §16.
PLUGIN_RESOURCE_RE = re.compile(
    r"<plugin>/"
    r"((?:skills/[A-Za-z0-9_.-]+/)?"
    r"(?:references|scripts|assets|templates|schemas|baselines)/"
    r"[A-Za-z0-9_./*?{}\[\]-]+)"
)

PLUGIN_MANIFESTS = ("plugin.json", ".claude-plugin/plugin.json")

ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:"
    r"[A-Za-z]:\\(?:[A-Za-z0-9_. -]+\\)*[A-Za-z0-9_. -]+"
    r"|"
    r"/(?:home|Users|mnt|opt|srv|var|tmp)/"
    r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+ -]+)*"
    r")"
)

URL_RE = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    re.IGNORECASE,
)

SHELL_EXECUTION_RE = re.compile(
    r"(?m)(?:^|[`$]\s*)"
    r"(?:bash|sh|zsh|fish|powershell|pwsh|cmd|python3?|node|npm|npx|pnpm|yarn)"
    r"\s+[^\n`]+"
)

DEPENDENCY_INSTALL_RE = re.compile(
    r"\b(?:pip(?:3)?\s+install|npm\s+install|npm\s+i\b|"
    r"pnpm\s+(?:add|install)|yarn\s+add|uv\s+(?:add|pip\s+install)|"
    r"apt(?:-get)?\s+install|brew\s+install)\b",
    re.IGNORECASE,
)

ENVIRONMENT_ACCESS_RE = re.compile(
    r"\b(?:process\.env|os\.environ|os\.getenv|System\.getenv|"
    r"\$ENV:|\$\{?[A-Z][A-Z0-9_]{2,}\}?)",
    re.IGNORECASE,
)

CREDENTIAL_ACCESS_RE = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|"
    r"credential|private[_-]?key|\.env|id_rsa|id_ed25519)\b",
    re.IGNORECASE,
)

DYNAMIC_IMPORT_RE = re.compile(
    r"\b(?:importlib\.import_module|__import__|dynamic\s+import|"
    r"import\s*\(|require\s*\([^'\"]|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)

ENCODED_CONTENT_RE = re.compile(
    r"\b(?:base64\s+(?:-d|--decode)|fromhex\s*\(|"
    r"atob\s*\(|decode64|xxd\s+-r)\b",
    re.IGNORECASE,
)

MCP_RE = re.compile(
    r"\b(?:MCP|Model Context Protocol|mcpServers|mcp-server|mcp_server)\b",
    re.IGNORECASE,
)

AUDIT_MANIPULATION_RE = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+"
    r"(?:rules|instructions)|"
    r"(?:return|mark\s+as)\s+(?:only\s+)?ready|"
    r"skip\s+(?:the\s+)?(?:audit|verification)|"
    r"do\s+not\s+(?:report|list)\s+findings|"
    r"pre[- ]approved|"
    r"trust\s+mode|"
    r"bypass\s+(?:the\s+)?(?:audit|review)",
    re.IGNORECASE,
)

NETWORK_TOOL_RE = re.compile(
    r"\b(?:WebFetch|curl|wget|fetch\s*\(|requests\.|httpx\.|axios\.|"
    r"https?\.request\s*\(|urllib\.request|Invoke-WebRequest)\b",
    re.IGNORECASE,
)

MANDATORY_ALTERNATIVE_RE = re.compile(
    r"\b(?:use|usar|utilize|invoke|hand\s+off\s+to)\s+"
    r"`?([a-z0-9]+(?:-[a-z0-9]+)+)`?",
    re.IGNORECASE,
)

BASH_COMMAND_RE = re.compile(
    r"(?m)(?:^|\n|`|\$)\s*"
    r"((?:bash|sh|zsh|python3?|node|npm|npx|pnpm|yarn)\s+"
    r"[A-Za-z0-9_./-]+(?:\s+[^\n`]*)?)"
)

# (pattern, operational effect, severity, replacement). Sources, dated, in
# references/model-profiles.md: Anthropic's prompting pages for Claude Opus 5,
# Sonnet 5 and the current-model best practices.
PROFILE_PHRASES = {
    "claude": [
        (
            re.compile(r"\bCRITICAL\s*:|\bYOU\s+MUST\b|\bMUST\s+ALWAYS\b"),
            "aggressive emphasis written for older models makes current models over-trigger",
            "Minor",
            "State the condition in plain words: 'Use X when ...'.",
        ),
        (
            re.compile(
                r"\b(?:if|when)\s+in\s+doubt,?\s+(?:use|run|call|invoke|load)\b|"
                r"\bdefault\s+to\s+using\b|"
                r"\bem\s+caso\s+de\s+d[úu]vida,?\s+(?:usa|corre|chama)\b",
                re.I,
            ),
            "a blanket default makes current models over-trigger the tool or skill",
            "Minor",
            "Name the situations where the tool helps instead of a default.",
        ),
        (
            re.compile(
                r"\bdouble[- ]check\b|\bre-?verify\b|\bverify\s+your\s+(?:work|answer)\b|"
                r"\bcheck\s+your\s+work\b|\buse\s+a\s+subagent\s+to\s+(?:verify|double[- ]check|review)\b|"
                r"\bverifica(?:r)?\s+(?:tudo\s+)?duas\s+vezes\b|\bvolta\s+a\s+verificar\b",
                re.I,
            ),
            "current Claude models already self-verify; an explicit re-check instruction causes over-verification",
            "Minor",
            "Remove it, or replace it with a concrete gate: 'Continue only when <command> exits 0'.",
        ),
        (
            re.compile(
                r"\bonly\s+report\s+(?:the\s+)?(?:high|critical)(?:[- ]severity)?\b|\bbe\s+conservative\b|"
                r"\bdo(?:\s+not|n'?t)\s+nitpick\b|\breporta\s+s[óo]\s+(?:o\s+)?(?:grave|cr[íi]tico)",
                re.I,
            ),
            "Sonnet 5 and Opus 5 follow a self-filter literally and drop real findings",
            "Minor",
            "Name the bar concretely ('report anything that could cause incorrect behaviour; omit pure style').",
        ),
        (
            re.compile(r"\b(?:do\s+not|don'?t)\s+(?:think|reason)\b|\bwithout\s+thinking\b", re.I),
            "an instruction not to think increases internal-tag leakage when thinking is disabled",
            "Minor",
            "Remove it; control cost with effort, not with an instruction.",
        ),
        (
            re.compile(r"\bafter\s+every\s+\d+\s+tool\s+calls?\b", re.I),
            "forced progress narration is scaffolding current models no longer need",
            "Nit",
            "Describe the update you want instead of a fixed cadence.",
        ),
    ],
}


class DuplicateKeyError(ValueError):
    """Raised when a YAML mapping contains duplicate keys."""


class UniqueKeyLoader(yaml.SafeLoader):
    """PyYAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)

        if key in mapping:
            raise DuplicateKeyError(f"duplicate YAML key: {key!r}")

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


@dataclass
class Finding:
    severity: str
    type: str
    confidence: str
    title: str
    location: str
    evidence: str
    impact: str
    fix: str
    owner: str = "Readiness"
    policy: str = ""


@dataclass
class SecurityHandoff:
    category: str
    location: str
    evidence: str
    reason: str
    recommended_next_step: str = "Run skill-security-auditor."


@dataclass
class TargetResult:
    skill: str
    skill_directory: str
    readiness_verdict: str
    depth: str
    model_profile: str
    profile_source: str
    security_status: str
    security_handoff_required: bool
    release_status: str
    frontmatter_valid: bool
    semantic_review_complete: bool = False
    discovered_resources: list[str] = field(default_factory=list)
    resolved_resources: list[str] = field(default_factory=list)
    unresolved_resources: list[str] = field(default_factory=list)
    commands_observed: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    security_handoffs: list[SecurityHandoff] = field(default_factory=list)
    mechanical_dimensions: dict[str, str] = field(default_factory=dict)
    semantic_checks_required: list[str] = field(default_factory=list)
    skipped_checks: list[dict[str, str]] = field(default_factory=list)


def clean_excerpt(value: str, limit: int = 300) -> str:
    compact = " ".join(value.strip().split())

    if len(compact) > limit:
        return compact[: limit - 3] + "..."

    return compact


def add_finding(
    findings: list[Finding],
    severity: str,
    type_: str,
    title: str,
    location: str,
    evidence: str,
    impact: str,
    fix: str,
    policy: str,
    confidence: str = "Observed",
) -> None:
    findings.append(
        Finding(
            severity=severity,
            type=type_,
            confidence=confidence,
            title=title,
            location=location,
            evidence=clean_excerpt(evidence),
            impact=impact,
            fix=fix,
            policy=policy,
        )
    )


def add_handoff(
    handoffs: list[SecurityHandoff],
    category: str,
    location: str,
    evidence: str,
    reason: str,
) -> None:
    normalized = (
        category,
        location,
        clean_excerpt(evidence),
    )

    for existing in handoffs:
        existing_key = (
            existing.category,
            existing.location,
            existing.evidence,
        )

        if existing_key == normalized:
            return

    handoffs.append(
        SecurityHandoff(
            category=category,
            location=location,
            evidence=clean_excerpt(evidence),
            reason=reason,
        )
    )


def is_excluded(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True

    return any(part in EXCLUDED_DIRECTORIES for part in relative.parts)


def read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    if b"\x00" in raw:
        return None

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def line_number_for(text: str, needle: str) -> int | None:
    if not needle:
        return None

    index = text.find(needle)

    if index < 0:
        return None

    return text.count("\n", 0, index) + 1


def location_for(path: Path, text: str, needle: str = "") -> str:
    line = line_number_for(text, needle)

    if line is None:
        return str(path)

    return f"{path}:{line}"


def normalize_tool_collection(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, str):
        return [
            part.strip()
            for part in value.split(",")
            if part.strip()
        ]

    return [str(value).strip()]


def extract_frontmatter(
    path: Path,
    text: str,
) -> tuple[str, dict[str, Any], int]:
    lines = text.splitlines()

    if not lines or lines[0].strip() != "---":
        raise ValueError("SKILL.md does not begin with '---' on line 1")

    closing_index: int | None = None

    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing_index = index
            break

    if closing_index is None:
        raise ValueError("YAML frontmatter has no closing '---' delimiter")

    raw = "\n".join(lines[1:closing_index])

    try:
        parsed = yaml.load(raw, Loader=UniqueKeyLoader)
    except DuplicateKeyError:
        raise
    except yaml.YAMLError as error:
        summary = str(error).splitlines()[0]
        raise ValueError(f"invalid YAML: {summary}") from error

    if not isinstance(parsed, dict):
        raise ValueError("frontmatter is not a YAML mapping")

    return raw, parsed, closing_index + 1


def discover_targets(
    target: Path,
    target_mode: str | None,
) -> tuple[list[Path], Path]:
    target = target.resolve()

    if target.is_file():
        if target.name != "SKILL.md":
            raise ValueError("A file target must be named SKILL.md")

        if target_mode == "repo":
            raise ValueError("--target repo requires a directory")

        return [target], target.parent

    if not target.is_dir():
        raise ValueError(f"Target does not exist: {target}")

    direct_skill = target / "SKILL.md"

    if target_mode == "skill":
        if not direct_skill.is_file():
            raise ValueError(
                "--target skill requires a directory containing SKILL.md"
            )

        return [direct_skill.resolve()], target

    if direct_skill.is_file() and target_mode != "repo":
        return [direct_skill.resolve()], target

    results: list[Path] = []

    for path in sorted(target.rglob("SKILL.md")):
        if is_excluded(path, target):
            continue

        results.append(path.resolve())

    if not results:
        raise ValueError(f"No SKILL.md found under {target}")

    return results, target


def determine_repository_root(
    skill_dir: Path,
    requested_root: Path,
) -> Path:
    requested_root = requested_root.resolve()

    # The git root first: a skill resolves the same resources whether it was
    # audited alone or found inside a directory of skills.
    current = skill_dir
    while True:
        if (current / ".git").exists():
            return current
        if current.parent == current:
            break
        current = current.parent

    if requested_root != skill_dir and requested_root in skill_dir.parents:
        return requested_root

    current = skill_dir

    while True:
        if (current / ".git").exists():
            return current

        if current.parent == current:
            break

        current = current.parent

    return skill_dir


def iter_text_files(skill_dir: Path) -> Iterable[Path]:
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file():
            continue

        if is_excluded(path, skill_dir):
            continue

        if path.name == "SKILL.md" or path.suffix.lower() in TEXT_EXTENSIONS:
            yield path


def normalize_resource_reference(reference: str) -> str:
    reference = reference.rstrip(".,;:)'\"`")

    # `[references/a.md](references/a.md)` captures `references/a.md]`, and
    # `{x, assets/}` captures `assets/}`. A closing bracket without its opener
    # is surrounding prose, not part of a glob.
    while reference[-1:] in ("]", "}"):
        opener = "[" if reference[-1] == "]" else "{"
        if reference.count(reference[-1]) <= reference.count(opener):
            break
        reference = reference[:-1].rstrip(".,;:)'\"`")

    return reference


def resource_matches(
    base: Path,
    reference: str,
) -> list[Path]:
    reference = normalize_resource_reference(reference)

    if any(character in reference for character in "*?[]"):
        return sorted(base.glob(reference))

    braces = re.search(r"\{([^{}]+)\}", reference)

    if braces:
        alternatives = braces.group(1).split(",")
        matches: list[Path] = []

        for alternative in alternatives:
            expanded = (
                reference[: braces.start()]
                + alternative
                + reference[braces.end() :]
            )
            candidate = base / expanded

            if candidate.exists():
                matches.append(candidate)

        return sorted(matches)

    candidate = base / reference
    return [candidate] if candidate.exists() else []


def plugin_root(skill_dir: Path) -> Path | None:
    for ancestor in skill_dir.resolve().parents:
        if any((ancestor / manifest).is_file() for manifest in PLUGIN_MANIFESTS):
            return ancestor
    return None


def resolve_resource(
    reference: str,
    skill_dir: Path,
    repository_root: Path,
) -> tuple[str, list[Path]]:
    local_matches = resource_matches(skill_dir, reference)

    if local_matches:
        return "skill", local_matches

    if repository_root != skill_dir:
        root_matches = resource_matches(repository_root, reference)

        if root_matches:
            return "repository", root_matches

    return "missing", []


def parse_bash_patterns(tools: Sequence[str]) -> list[str]:
    patterns: list[str] = []

    for tool in tools:
        for match in re.findall(r"Bash\(([^)]*)\)", tool):
            patterns.append(match.strip())

        if tool.strip() == "Bash":
            patterns.append("*")

    return patterns


def glob_command_match(command: str, pattern: str) -> bool:
    normalized_command = " ".join(command.split())
    normalized_pattern = " ".join(pattern.split())

    if normalized_pattern == "*":
        return True

    if normalized_pattern.endswith(":*"):
        prefix = normalized_pattern[:-2]
        return normalized_command == prefix or normalized_command.startswith(
            prefix + " "
        )

    shell_pattern = normalized_pattern.replace(":*", "*")
    return fnmatch.fnmatchcase(normalized_command, shell_pattern)


def command_is_permitted(
    command: str,
    allowed_tools: Sequence[str],
) -> bool:
    patterns = parse_bash_patterns(allowed_tools)

    if not patterns:
        return False

    return any(glob_command_match(command, pattern) for pattern in patterns)


def extract_commands(text: str) -> list[str]:
    commands: list[str] = []

    for match in BASH_COMMAND_RE.finditer(text):
        command = clean_excerpt(match.group(1), 500)

        if command and command not in commands:
            commands.append(command)

    return commands


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


def verdict_for(findings: Sequence[Finding]) -> str:
    highest = max(
        (SEVERITY_WEIGHT.get(item.severity, 0) for item in findings),
        default=0,
    )

    if highest >= 4:
        return "Reject"

    if highest == 3:
        return "Needs revision"

    if highest in {1, 2}:
        return "Approve with nits"

    if findings and all(item.type == "Suggestion" for item in findings):
        return "Ready with suggestions"

    return "Ready"


def release_status_for(
    readiness_verdict: str,
    handoff_required: bool,
) -> str:
    if readiness_verdict == "Reject":
        return "Reject"

    if readiness_verdict == "Needs revision":
        return "Needs revision"

    if handoff_required:
        return "Security review required"

    return "Await independent security review"


def check_frontmatter(
    skill_md: Path,
    skill_dir: Path,
    text: str,
    frontmatter: dict[str, Any],
    frontmatter_end_line: int,
    findings: list[Finding],
) -> None:
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    allowed_tools = frontmatter.get("allowed-tools")
    effort = frontmatter.get("effort")
    model = frontmatter.get("model")
    argument_hint = frontmatter.get("argument-hint")

    if not isinstance(name, str) or not re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*",
        name or "",
    ):
        add_finding(
            findings,
            "Blocker",
            "Defect",
            "Missing or invalid skill name",
            f"{skill_md}:1-{frontmatter_end_line}",
            repr(name),
            "The harness cannot identify or route the skill reliably.",
            "Declare a non-empty kebab-case name.",
            "§3.1 Name",
        )
    elif name != skill_dir.name:
        add_finding(
            findings,
            "Major",
            "Defect",
            "Skill name does not match the containing folder",
            location_for(skill_md, text, f"name: {name}"),
            f"name={name!r}; folder={skill_dir.name!r}",
            "Routing, packaging, and repository identity can disagree.",
            "Rename the folder or change name so they match.",
            "§3.1 Name",
        )

    if not isinstance(description, str) or not description.strip():
        add_finding(
            findings,
            "Blocker",
            "Defect",
            "Missing or empty description",
            f"{skill_md}:1-{frontmatter_end_line}",
            repr(description),
            "The routing layer cannot determine when to activate the skill.",
            "Add a concise description with positive and negative boundaries.",
            "§3.2 Description",
        )
    else:
        if not begins_with_action(description):
            add_finding(
                findings,
                "Minor",
                "Defect",
                "Description does not begin with a clear action verb",
                location_for(skill_md, text, "description:"),
                description,
                "The routing intent is less explicit.",
                "Begin with an action such as Audit, Review, Check, Generate, or Validate.",
                "§3.2 Description",
            )

        if not description_has_when_to_use(description):
            add_finding(
                findings,
                "Major",
                "Defect",
                "Description has no clear activation condition",
                location_for(skill_md, text, "description:"),
                description,
                "The router cannot reliably distinguish intended invocations.",
                "State when or at which lifecycle stage the skill should be used.",
                "§6 Trigger discrimination",
            )

        if len(description) > 700:
            add_finding(
                findings,
                "Minor",
                "Concern",
                "Description is too long for efficient routing",
                location_for(skill_md, text, "description:"),
                f"{len(description)} characters",
                "Implementation detail can obscure the activation boundary.",
                "Keep routing criteria in the description and move workflow detail into the body.",
                "§3.2 Description",
            )

    if allowed_tools is None:
        add_finding(
            findings,
            "Major",
            "Defect",
            "Missing allowed-tools declaration",
            f"{skill_md}:1-{frontmatter_end_line}",
            "allowed-tools is absent",
            "The workflow has no explicit capability contract.",
            "Declare allowed-tools, even when the list is empty.",
            "§3.3 Allowed tools",
        )
    elif not isinstance(allowed_tools, (str, list)):
        add_finding(
            findings,
            "Major",
            "Defect",
            "allowed-tools has an unsupported value type",
            location_for(skill_md, text, "allowed-tools:"),
            repr(allowed_tools),
            "Adapters may not interpret the capability declaration.",
            "Use a list or the repository-supported string format.",
            "§3.3 Allowed tools",
        )

    if model is not None and model not in VALID_MODELS:
        add_finding(
            findings,
            "Major",
            "Defect",
            "Unresolvable model identifier",
            location_for(skill_md, text, "model:"),
            repr(model),
            "The target harness may be unable to select the requested model.",
            f"Use one of {sorted(VALID_MODELS)} or omit the field.",
            "§3.4 Optional fields",
        )

    if effort is not None and effort not in VALID_EFFORTS:
        add_finding(
            findings,
            "Minor",
            "Defect",
            "Invalid effort value",
            location_for(skill_md, text, "effort:"),
            repr(effort),
            "The harness may ignore or reject the effort configuration.",
            f"Use one of {sorted(VALID_EFFORTS)}.",
            "§3.4 Optional fields",
        )

    if argument_hint is None:
        body_uses_arguments = bool(
            re.search(
                r"\b(?:argument|arguments|--target|--depth|<target>|<path>)\b",
                text,
                re.I,
            )
        )

        if body_uses_arguments:
            add_finding(
                findings,
                "Minor",
                "Concern",
                "Skill uses invocation arguments but has no argument-hint",
                f"{skill_md}:1-{frontmatter_end_line}",
                "argument-hint is absent",
                "Users and routing tools may not know the expected invocation syntax.",
                "Add argument-hint describing the accepted target and options.",
                "§3.4 Optional fields",
            )

    top_level_keys = len(frontmatter)

    if top_level_keys <= 2 and len(text.splitlines()) > 20:
        add_finding(
            findings,
            "Major",
            "Defect",
            "Non-trivial skill has minimal frontmatter",
            f"{skill_md}:1-{frontmatter_end_line}",
            f"{top_level_keys} top-level fields; {len(text.splitlines())} total lines",
            "The skill omits capability and execution metadata expected by the harness.",
            "Declare allowed-tools and relevant optional execution fields.",
            "§5 Minimal frontmatter",
        )


def check_description_routing(
    skill_md: Path,
    skill_dir: Path,
    text: str,
    description: str,
    findings: list[Finding],
) -> None:
    if not description:
        return

    alternatives = extract_mandatory_alternatives(description)

    for alternative in sorted(alternatives):
        if alternative == skill_dir.name:
            continue

        if not sibling_skill_exists(skill_dir, alternative):
            add_finding(
                findings,
                "Major",
                "Defect",
                "Description routes to an unavailable mandatory skill",
                location_for(skill_md, text, alternative),
                alternative,
                "The documented handoff cannot be completed in the installed skill set.",
                f"Install `{alternative}`, mark it optional, or change the handoff.",
                "§24 Repository routing",
            )

    installed_siblings = [
        item.name
        for item in skill_dir.parent.iterdir()
        if item.is_dir()
        and item != skill_dir
        and (item / "SKILL.md").is_file()
    ]

    named_siblings = {
        sibling
        for sibling in installed_siblings
        if sibling in description
    }

    if named_siblings and not description_has_negative_boundary(description):
        add_finding(
            findings,
            "Major",
            "Defect",
            "Description names adjacent skills without a negative routing boundary",
            location_for(skill_md, text, "description:"),
            description,
            "The router may activate overlapping skills for the same request.",
            "State when not to use this skill and identify the correct handoff.",
            "§6 Trigger discrimination",
        )


def check_read_only_permissions(
    skill_md: Path,
    text: str,
    frontmatter: dict[str, Any],
    findings: list[Finding],
) -> None:
    if not claims_read_only(text):
        return

    allowed = {
        item.lower()
        for item in normalize_tool_collection(frontmatter.get("allowed-tools"))
    }
    # `Write` creates a report; `Edit` changes what exists. An auditor that
    # writes its report is still read-only toward its target.
    writers = sorted(t for t in ("edit", "multiedit", "notebookedit") if t in allowed)
    if writers:
        add_finding(
            findings,
            "Major",
            "Defect",
            "Skill claims to be read-only but allows write tools",
            location_for(skill_md, text, "allowed-tools:"),
            json.dumps(writers),
            "The declared operating mode and the capability contract disagree.",
            "Drop the write tools, or drop the read-only claim.",
            "§14 Permission coherence",
        )
        return

    denied = {
        item.lower()
        for item in normalize_tool_collection(frontmatter.get("disallowed-tools"))
    }

    for required in ("edit", "multiedit", "notebookedit"):
        if not any(required in item for item in denied):
            add_finding(
                findings,
                "Major",
                "Defect",
                f"Read-only skill does not deny {required}",
                location_for(skill_md, text, "disallowed-tools:"),
                json.dumps(sorted(denied)),
                "The active adapter may expose a write capability that contradicts the operating mode.",
                f"Add {required} to disallowed-tools.",
                "§14 Permission coherence",
            )


READ_ONLY_RE = re.compile(r"\bread[- ]only\b", re.I)
# "not read-only", "não é read-only", "no es read-only", "isn't read-only".
NEGATED_BEFORE_RE = re.compile(
    r"\b(?:not|never|isn'?t|no|n[ãa]o|nao|nunca)\b(?:\s+(?:is|é|e|es|a|um|uma))?\s*$",
    re.I,
)


def claims_read_only(text: str) -> bool:
    for match in READ_ONLY_RE.finditer(text):
        before = text[max(0, match.start() - 24):match.start()]
        if not NEGATED_BEFORE_RE.search(before):
            return True
    return False


def check_permission_commands(
    skill_md: Path,
    text: str,
    frontmatter: dict[str, Any],
    findings: list[Finding],
) -> list[str]:
    commands = extract_commands(text)
    allowed_tools = normalize_tool_collection(frontmatter.get("allowed-tools"))

    for command in commands:
        executable = command.split()[0]

        if executable not in {
            "bash",
            "sh",
            "zsh",
            "python",
            "python3",
            "node",
            "npm",
            "npx",
            "pnpm",
            "yarn",
        }:
            continue

        if not command_is_permitted(command, allowed_tools):
            add_finding(
                findings,
                "Major",
                "Defect",
                "Documented command is not matched by allowed-tools",
                location_for(skill_md, text, command),
                command,
                "The target adapter may block the documented workflow command.",
                "Add a narrowly scoped Bash permission matching the complete invocation.",
                "§14 Permission coherence",
            )

    return commands


def check_hooks_and_subagents(
    skill_md: Path,
    text: str,
    frontmatter: dict[str, Any],
    findings: list[Finding],
    handoffs: list[SecurityHandoff],
) -> None:
    if "hooks" in frontmatter:
        description = str(frontmatter.get("description", ""))

        if not re.search(r"\bhooks?\b", description, re.I):
            add_finding(
                findings,
                "Major",
                "Defect",
                "Hooks are not disclosed in the description",
                location_for(skill_md, text, "hooks:"),
                "hooks declared in frontmatter",
                "Users may activate a session-wide effect without a routing-level warning.",
                "Declare the hook behavior in the description.",
                "§15 Hooks and subagents",
            )

        add_handoff(
            handoffs,
            "persistent-hook",
            location_for(skill_md, text, "hooks:"),
            "hooks declared in frontmatter",
            "The security auditor must assess persistence and session impact.",
        )

    if (
        "agent" in frontmatter or "background" in frontmatter
    ) and frontmatter.get("context") != "fork":
        key = "agent:" if "agent" in frontmatter else "background:"

        add_finding(
            findings,
            "Major",
            "Defect",
            "Subagent declaration lacks required fork context",
            location_for(skill_md, text, key),
            f"context={frontmatter.get('context')!r}",
            "The target adapter may ignore the declaration or run it in the wrong context.",
            "Add context: fork when required by the adapter.",
            "§15 Hooks and subagents",
        )


def check_body_size(
    skill_md: Path,
    text: str,
    findings: list[Finding],
) -> None:
    line_count = len(text.splitlines())

    if line_count > 800:
        add_finding(
            findings,
            "Major",
            "Defect",
            "SKILL.md exceeds 800 lines",
            f"{skill_md}:1-{line_count}",
            f"{line_count} lines",
            "The operational manifest is too large for reliable routing and context use.",
            "Move policy, examples, and supporting material into references.",
            "§19 Body size",
        )
    elif line_count > 500:
        add_finding(
            findings,
            "Minor",
            "Concern",
            "SKILL.md exceeds the preferred 500-line limit",
            f"{skill_md}:1-{line_count}",
            f"{line_count} lines",
            "The manifest is approaching an inefficient operational size.",
            "Move supporting material into references.",
            "§19 Body size",
        )


def check_absolute_paths(
    skill_md: Path,
    text: str,
    findings: list[Finding],
) -> None:
    matches = sorted(set(ABSOLUTE_PATH_RE.findall(text)))

    if not matches:
        return

    machine_specific_declared = bool(
        re.search(
            r"\b(?:machine[- ]specific|local\s+path|"
            r"paths?\s+(?:are|is)\s+local|desta\s+m[aá]quina)\b",
            text,
            re.I,
        )
    )

    severity = "Nit" if machine_specific_declared else "Minor"
    type_ = "Suggestion" if machine_specific_declared else "Defect"

    add_finding(
        findings,
        severity,
        type_,
        "Absolute machine path detected",
        str(skill_md),
        ", ".join(matches[:3]),
        "The workflow may fail on another machine or installation path.",
        (
            "Keep the explicit machine-specific declaration."
            if machine_specific_declared
            else "Replace the path with a relative or configurable path."
        ),
        "§18 Portability",
    )


def check_resources(
    skill_md: Path,
    skill_dir: Path,
    repository_root: Path,
    text: str,
    findings: list[Finding],
) -> tuple[list[str], list[str], list[str]]:
    plugin_references = {
        normalize_resource_reference(match)
        for match in PLUGIN_RESOURCE_RE.findall(text)
    }
    # `${CLAUDE_SKILL_DIR}/scripts/x` is this skill's own `scripts/x`.
    local_text = text.replace("${CLAUDE_SKILL_DIR}/", "")
    references = sorted(
        {
            normalize_resource_reference(match)
            for match in RESOURCE_REFERENCE_RE.findall(local_text)
        }
        | plugin_references
    )
    shared_root = plugin_root(skill_dir) if plugin_references else None
    # A skill in a project's `.claude/skills` or `.agents/skills` ships with
    # the repository; reaching a repository file is its design, not coupling.
    project_skill = is_project_skill(skill_dir)

    resolved: list[str] = []
    unresolved: list[str] = []

    for reference in references:
        scope, matches = resolve_resource(
            reference,
            skill_dir,
            repository_root,
        )

        if (
            scope != "skill"
            and reference in plugin_references
            and shared_root is not None
        ):
            shared = resource_matches(shared_root, reference)
            if shared:
                resolved.extend(
                    "<plugin>/" + path.relative_to(shared_root).as_posix()
                    for path in shared
                )
                continue

        if scope == "skill":
            resolved.extend(
                path.relative_to(skill_dir).as_posix()
                for path in matches
            )
            continue

        if scope == "repository":
            resolved.extend(
                path.relative_to(repository_root).as_posix()
                for path in matches
            )

            if project_skill:
                continue

            add_finding(
                findings,
                "Minor",
                "Concern",
                "Resource resolves only from the repository root",
                location_for(skill_md, text, reference),
                reference,
                "The skill may break when installed independently.",
                "Move the resource into the skill bundle or declare the shared-resource packaging contract.",
                "§16 Local resources",
                confidence="Inferred",
            )
            continue

        if reference in plugin_references and shared_root is None:
            # `<plugin>/…` names a file of a plugin this skill is not part of.
            add_finding(
                findings,
                "Nit",
                "Concern",
                "Plugin resource cannot be resolved from here",
                location_for(skill_md, text, reference),
                reference,
                "The path depends on where another plugin is installed.",
                "Name the plugin and skill the file belongs to, so the reader can find it.",
                "§16 Local resources",
                confidence="Inferred",
            )
            continue

        unresolved.append(reference)

        central_script = "scripts/" in reference
        severity = "Blocker" if central_script else "Major"

        add_finding(
            findings,
            severity,
            "Defect",
            "Referenced local resource is missing",
            location_for(skill_md, text, reference),
            reference,
            (
                "The documented workflow cannot execute its referenced script."
                if central_script
                else "The workflow depends on unavailable supporting material."
            ),
            f"Create `{reference}` inside the skill bundle or remove the reference.",
            "§16 Local resources",
        )

    return references, sorted(set(resolved)), unresolved


def is_project_skill(skill_dir: Path) -> bool:
    parts = skill_dir.parts
    return any(
        parts[i] in (".claude", ".agents") and parts[i + 1] == "skills"
        for i in range(len(parts) - 1)
    )


# Hard limits of the Agent Skills format (Anthropic, "Skill authoring best
# practices"): the harness rejects or truncates past them.
NAME_MAX, DESCRIPTION_MAX = 64, 1024
RESERVED_NAME_RE = re.compile(r"anthropic|claude")
XML_TAG_RE = re.compile(r"<[A-Za-z/][^<>]*>")
PERSON_RE = re.compile(
    r"^\s*(?:I|I'm|I'll|We|You|Eu|Posso|Podes|Puedo|Puedes)\b|"
    r"\b(?:I\s+can|I\s+will|you\s+can\s+use\s+this)\b",
    re.I,
)
MONTHS = (r"(?:January|February|March|April|May|June|July|August|September|October|"
          r"November|December|janeiro|fevereiro|mar[çc]o|abril|maio|junho|julho|agosto|"
          r"setembro|outubro|novembro|dezembro)")
TIME_SENSITIVE_RE = re.compile(
    r"\b(?:before|after|until|as\s+of|since|antes\s+de|depois\s+de|at[ée])\s+"
    + MONTHS + r"(?:\s+de)?\s+20\d\d\b|\bas\s+of\s+20\d\d\b",
    re.I,
)


def check_platform_rules(
    skill_md: Path,
    text: str,
    frontmatter: dict[str, Any],
    findings: list[Finding],
) -> None:
    """The format's hard limits, plus two authoring rules the docs single out."""
    name = str(frontmatter.get("name") or "")
    description = str(frontmatter.get("description") or "")
    rule = "§3.5 Agent Skills format"

    def flag(severity: str, title: str, evidence: str, impact: str, fix: str) -> None:
        add_finding(findings, severity, "Defect", title,
                    location_for(skill_md, text, evidence[:40]), evidence, impact, fix, rule)

    if len(name) > NAME_MAX:
        flag("Blocker", "Skill name exceeds 64 characters", name,
             "The harness rejects the skill.", "Shorten the name.")
    if RESERVED_NAME_RE.search(name):
        flag("Blocker", "Skill name uses a reserved word", name,
             "'anthropic' and 'claude' are reserved in skill names.", "Rename the skill.")
    if len(description) > DESCRIPTION_MAX:
        flag("Blocker", "Description exceeds 1024 characters", description[:80],
             "The harness truncates or rejects it; routing text is lost.",
             "Keep when-to-use in the description; move detail into the body.")
    for field, value in (("name", name), ("description", description)):
        tag = XML_TAG_RE.search(value)
        if tag:
            flag("Major", f"XML tag in {field}", tag.group(0),
                 "The format forbids XML tags in the frontmatter fields the router reads.",
                 "Remove the tag.")
    person = PERSON_RE.search(description)
    if person:
        flag("Minor", "Description is not written in the third person", person.group(0),
             "The description is injected into the system prompt; a first- or second-person "
             "voice degrades discovery.",
             "Write 'Extracts …, Use when …' instead of 'I can …' or 'You can …'.")
    dated = TIME_SENSITIVE_RE.search(text)
    if dated:
        flag("Minor", "Time-sensitive instruction", dated.group(0),
             "The instruction becomes wrong on a date nobody will remember to check.",
             "Describe the current behaviour; move the old one to an 'Old patterns' section.")


MARKDOWN_LINK_RE = re.compile(r"\]\((?!https?:|#|mailto:)([^)#\s]+\.md)\)")
TOC_RE = re.compile(r"^#{1,3}\s*(?:contents|table\s+of\s+contents|[íi]ndice|contenido|sum[áa]rio)\b",
                    re.I | re.M)


def check_reference_files(
    skill_dir: Path,
    resolved: list[str],
    findings: list[Finding],
) -> None:
    """References one level deep, and long ones navigable (Anthropic best practices)."""
    for relative in resolved:
        path = skill_dir / relative
        if path.suffix != ".md" or not path.is_file() or path.name == "SKILL.md":
            continue
        text = read_text(path) or ""
        nested = MARKDOWN_LINK_RE.search(text)
        if nested:
            add_finding(findings, "Nit", "Suggestion", "Reference links to a further reference",
                        location_for(path, text, nested.group(1)), nested.group(1),
                        "The model may only preview a file reached through another file.",
                        "Link every reference directly from SKILL.md.", "§16 Local resources",
                        confidence="Inferred")
        lines = text.count("\n")
        if lines > 100 and not TOC_RE.search(text):
            add_finding(findings, "Nit", "Suggestion", "Long reference has no table of contents",
                        f"{path}:1", f"{lines} lines",
                        "A partial read cannot see what the file covers.",
                        "Add a 'Contents' list at the top.", "§16 Local resources")


def check_scripts(
    skill_dir: Path,
    findings: list[Finding],
) -> None:
    scripts_dir = skill_dir / "scripts"

    if not scripts_dir.is_dir():
        return

    for script in sorted(scripts_dir.rglob("*")):
        if not script.is_file() or is_excluded(script, skill_dir):
            continue

        suffix = script.suffix.lower()

        if suffix not in SCRIPT_EXTENSIONS:
            continue

        text = read_text(script)

        if text is None:
            continue

        relative = script.relative_to(skill_dir).as_posix()
        first_line = text.splitlines()[0] if text.splitlines() else ""

        # An imported module is not executed directly; only an entry point
        # needs an interpreter line.
        entry_point = suffix != ".py" or "__main__" in text
        if suffix in DIRECT_EXECUTION_EXTENSIONS and entry_point and not first_line.startswith("#!"):
            add_finding(
                findings,
                "Minor",
                "Defect",
                "Script has no interpreter shebang",
                relative,
                first_line or "<empty file>",
                "Direct execution may fail or use an unexpected interpreter.",
                "Add an appropriate shebang or document interpreter-only invocation.",
                "§17 Script readiness",
            )

        if os.name != "nt":
            try:
                mode = script.stat().st_mode
            except OSError:
                mode = 0

            if not mode & stat.S_IXUSR:
                add_finding(
                    findings,
                    "Nit",
                    "Suggestion",
                    "Script is not owner-executable",
                    relative,
                    oct(mode),
                    "Direct execution requires an explicit interpreter.",
                    "Set the executable bit if direct execution is intended.",
                    "§17 Script readiness",
                )


def check_model_fit(
    skill_md: Path,
    text: str,
    profile: str,
    profile_source: str,
    findings: list[Finding],
) -> None:
    if profile == "generic":
        return

    # A phrase inside a fenced block is an illustration ("Avoid: ..."), not an
    # instruction the model receives as one.
    fences = [m.span() for m in re.finditer(r"^```.*?^```", text, re.M | re.S)]

    for pattern, impact, severity, replacement in PROFILE_PHRASES.get(profile, []):
        for match in pattern.finditer(text):
            if any(start <= match.start() < end for start, end in fences):
                continue
            phrase = match.group(0)

            add_finding(
                findings,
                severity,
                "Defect",
                f"Instruction conflicts with the {profile} profile",
                location_for(skill_md, text, phrase),
                f"{phrase!r}; profile resolved from {profile_source}",
                impact[0].upper() + impact[1:] + ".",
                replacement,
                "§12 Model fit",
            )


DISALLOWED_TOOLS_RE = re.compile(
    r"^disallowed-tools:\s*(?:.*?)(?=^\S|\Z)",
    re.M | re.S,
)


def denied_capability_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges of the `disallowed-tools` frontmatter block.

    A tool named there is a denial, not a capability. Handing it to the
    security auditor as an observed capability wastes the handoff.
    """
    return [match.span() for match in DISALLOWED_TOOLS_RE.finditer(text)]


def scan_security_handoffs(
    skill_dir: Path,
    handoffs: list[SecurityHandoff],
) -> None:
    checks = [
        (
            "external-url",
            URL_RE,
            "External resources require classification and security review.",
        ),
        (
            "network-capability",
            NETWORK_TOOL_RE,
            "Network capability requires least-privilege and destination review.",
        ),
        (
            "shell-execution",
            SHELL_EXECUTION_RE,
            "Shell execution requires security assessment.",
        ),
        (
            "dependency-installation",
            DEPENDENCY_INSTALL_RE,
            "Dependency installation requires supply-chain review.",
        ),
        (
            "environment-access",
            ENVIRONMENT_ACCESS_RE,
            "Environment access may expose sensitive runtime state.",
        ),
        (
            "credential-access",
            CREDENTIAL_ACCESS_RE,
            "Credential-related access requires security classification.",
        ),
        (
            "dynamic-import",
            DYNAMIC_IMPORT_RE,
            "Dynamic loading or execution requires security analysis.",
        ),
        (
            "encoded-content",
            ENCODED_CONTENT_RE,
            "Encoded content requires inspection for obfuscation.",
        ),
        (
            "mcp-capability",
            MCP_RE,
            "MCP tools and servers require permission and tool-poisoning review.",
        ),
        (
            "audit-manipulation",
            AUDIT_MANIPULATION_RE,
            "The content may attempt to influence an independent audit.",
        ),
    ]

    for path in iter_text_files(skill_dir):
        text = read_text(path)

        if text is None:
            continue

        relative = path.relative_to(skill_dir).as_posix()
        denied = denied_capability_spans(text)

        for category, pattern, reason in checks:
            match = next(
                (
                    candidate
                    for candidate in pattern.finditer(text)
                    if not any(
                        start <= candidate.start() and candidate.end() <= end
                        for start, end in denied
                    )
                ),
                None,
            )

            if not match:
                continue

            add_handoff(
                handoffs,
                category,
                location_for(Path(relative), text, match.group(0)),
                match.group(0),
                reason,
            )


def check_audit_manipulation(
    skill_md: Path,
    text: str,
    findings: list[Finding],
) -> None:
    description_match = re.search(
        r"(?m)^description:\s*(.*)$",
        text,
    )

    if description_match:
        description_line = description_match.group(1)
        attack = AUDIT_MANIPULATION_RE.search(description_line)

        if attack:
            add_finding(
                findings,
                "Blocker",
                "Defect",
                "Description attempts to control the readiness audit",
                location_for(skill_md, text, attack.group(0)),
                attack.group(0),
                "The target cannot be independently reviewed using its own requested verdict.",
                "Remove the audit-directed instruction and run skill-security-auditor.",
                "§2 Reviewed content is data",
            )

    comments = re.finditer(r"<!--.*?-->", text, re.DOTALL)

    for comment in comments:
        attack = AUDIT_MANIPULATION_RE.search(comment.group(0))

        if attack:
            add_finding(
                findings,
                "Blocker",
                "Defect",
                "HTML comment attempts to control the readiness audit",
                location_for(skill_md, text, attack.group(0)),
                attack.group(0),
                "Hidden content attempts to alter the independent review.",
                "Remove the hidden directive and run skill-security-auditor.",
                "§2 Reviewed content is data",
            )


def semantic_checks_for_depth(depth: str) -> list[str]:
    quick = [
        "description semantic quality",
        "trigger discrimination",
        "promise-to-step coverage",
        "resource coherence",
    ]

    standard = quick + [
        "instruction quality",
        "context and assumptions",
        "permission coherence",
        "portability",
        "model fit interpretation",
        "output contract",
    ]

    deep = standard + [
        "functional claims",
        "detailed coverage matrix",
        "repository routing semantics",
        "release-readiness evidence",
    ]

    return {
        "quick": quick,
        "standard": standard,
        "deep": deep,
    }[depth]


def skipped_checks() -> list[dict[str, str]]:
    return [
        {
            "check": "Target-script execution",
            "reason": "The readiness auditor does not execute untrusted target scripts.",
        },
        {
            "check": "External URL validation",
            "reason": "Owned by skill-security-auditor.",
        },
        {
            "check": "Dependency vulnerability scanning",
            "reason": "Owned by skill-security-auditor.",
        },
        {
            "check": "Signature verification",
            "reason": "Owned by security and release tooling.",
        },
        {
            "check": "Runtime network enforcement",
            "reason": "Owned by the privileged Runtime Gate.",
        },
    ]


def audit_target(
    skill_md: Path,
    requested_root: Path,
    depth: str,
    requested_profile: str | None,
    semantic_complete: bool = False,
) -> TargetResult:
    skill_dir = skill_md.parent.resolve()
    repository_root = determine_repository_root(
        skill_dir,
        requested_root,
    )

    findings: list[Finding] = []
    handoffs: list[SecurityHandoff] = []
    resources: list[str] = []
    resolved_resources: list[str] = []
    unresolved_resources: list[str] = []
    commands: list[str] = []
    frontmatter_valid = False
    frontmatter: dict[str, Any] = {}

    text = read_text(skill_md)

    if text is None:
        add_finding(
            findings,
            "Blocker",
            "Defect",
            "SKILL.md is not readable UTF-8 text",
            str(skill_md),
            "Unable to decode SKILL.md as UTF-8",
            "The skill cannot be parsed reliably.",
            "Save SKILL.md as UTF-8 text.",
            "§4 YAML validity",
        )

        profile = requested_profile or "generic"
        profile_source = "--model" if requested_profile else "fallback"
    else:
        try:
            _, frontmatter, end_line = extract_frontmatter(
                skill_md,
                text,
            )
            frontmatter_valid = True
        except Exception as error:
            add_finding(
                findings,
                "Blocker",
                "Defect",
                "Invalid YAML frontmatter",
                f"{skill_md}:1",
                str(error),
                "The skill cannot be loaded or routed reliably.",
                "Add valid YAML frontmatter beginning on line 1.",
                "§4 YAML validity",
            )
            end_line = 1

        profile, profile_source = resolve_profile(
            requested_profile,
            frontmatter,
            skill_dir,
        )

        if frontmatter_valid:
            check_frontmatter(
                skill_md,
                skill_dir,
                text,
                frontmatter,
                end_line,
                findings,
            )

            description = str(frontmatter.get("description", ""))

            check_platform_rules(skill_md, text, frontmatter, findings)

            check_description_routing(
                skill_md,
                skill_dir,
                text,
                description,
                findings,
            )

            check_read_only_permissions(
                skill_md,
                text,
                frontmatter,
                findings,
            )

            commands = check_permission_commands(
                skill_md,
                text,
                frontmatter,
                findings,
            )

            check_hooks_and_subagents(
                skill_md,
                text,
                frontmatter,
                findings,
                handoffs,
            )

        check_body_size(skill_md, text, findings)
        check_absolute_paths(skill_md, text, findings)

        (
            resources,
            resolved_resources,
            unresolved_resources,
        ) = check_resources(
            skill_md,
            skill_dir,
            repository_root,
            text,
            findings,
        )

        check_scripts(skill_dir, findings)
        check_reference_files(skill_dir, resolved_resources, findings)

        check_model_fit(
            skill_md,
            text,
            profile,
            profile_source,
            findings,
        )

        check_audit_manipulation(
            skill_md,
            text,
            findings,
        )

        scan_security_handoffs(
            skill_dir,
            handoffs,
        )

    verdict = verdict_for(findings)
    handoff_required = bool(handoffs)
    security_status = (
        "Handoff required"
        if handoff_required
        else "Not performed"
    )

    dimensions = {
        "frontmatter": (
            "Pass"
            if frontmatter_valid
            else "Fail"
        ),
        "description": (
            "Mechanical checks completed"
            if frontmatter_valid
            else "Blocked by invalid frontmatter"
        ),
        "local-resources": (
            "Pass"
            if not unresolved_resources
            else "Fail"
        ),
        "permission-coherence": (
            "Mechanical checks completed"
            if frontmatter_valid
            else "Blocked by invalid frontmatter"
        ),
        "portability": "Mechanical checks completed",
        "model-fit": (
            "Mechanical phrase checks completed"
            if profile != "generic"
            else "Generic profile; universal checks only"
        ),
        "semantic-review": (
            "Completed"
            if semantic_complete
            else "Required"
        ),
        "security-review": "Not performed",
    }

    return TargetResult(
        skill=str(skill_md),
        skill_directory=str(skill_dir),
        readiness_verdict=verdict,
        depth=depth,
        model_profile=profile,
        profile_source=profile_source,
        security_status=security_status,
        security_handoff_required=handoff_required,
        release_status=release_status_for(
            verdict,
            handoff_required,
        ),
        frontmatter_valid=frontmatter_valid,
        semantic_review_complete=semantic_complete,
        discovered_resources=resources,
        resolved_resources=resolved_resources,
        unresolved_resources=unresolved_resources,
        commands_observed=commands,
        findings=findings,
        security_handoffs=handoffs,
        mechanical_dimensions=dimensions,
        semantic_checks_required=semantic_checks_for_depth(depth),
        skipped_checks=skipped_checks(),
    )


def finding_sort_key(item: Finding) -> tuple[int, str, str]:
    return (
        -SEVERITY_WEIGHT.get(item.severity, 0),
        item.location,
        item.title,
    )


def result_to_dict(result: TargetResult) -> dict[str, Any]:
    payload = asdict(result)
    payload["findings"] = [
        asdict(item)
        for item in sorted(
            result.findings,
            key=finding_sort_key,
        )
    ]
    return payload


def print_markdown(
    results: Sequence[TargetResult],
    target_root: Path,
) -> None:
    print("# skill-readiness-auditor · mechanical report")
    print()
    print(f"**Version:** {VERSION}  ")
    print(f"**Target root:** `{target_root}`  ")
    print(f"**Targets:** {len(results)}")
    print()

    if len(results) > 5:
        print(
            "> Mechanical checks covered all targets. "
            "Split semantic review into deterministic batches of five."
        )
        print()

    for result in results:
        print(f"## {result.skill_directory}")
        print()
        print(
            f"**Readiness verdict:** "
            f"{result.readiness_verdict}  "
        )
        print(f"**Depth requested:** {result.depth}  ")
        print(
            f"**Model profile:** {result.model_profile}  "
        )
        print(
            f"**Profile resolved from:** "
            f"{result.profile_source}  "
        )
        print(
            f"**Security status:** "
            f"{result.security_status}  "
        )
        print(
            f"**Release status:** "
            f"{result.release_status}"
        )
        print()

        print("### Mechanical dimensions")
        print()
        print("| Dimension | State |")
        print("|---|---|")

        for dimension, state in result.mechanical_dimensions.items():
            print(f"| {dimension} | {state} |")

        print()

        ordered_findings = sorted(
            result.findings,
            key=finding_sort_key,
        )

        if ordered_findings:
            print(f"### Findings ({len(ordered_findings)})")
            print()
            print(
                "| # | Severity | Type | Confidence | "
                "Title | Location |"
            )
            print(
                "|---:|---|---|---|---|---|"
            )

            for index, item in enumerate(
                ordered_findings,
                start=1,
            ):
                title = item.title.replace("|", "\\|")
                location = item.location.replace("|", "\\|")

                print(
                    f"| {index} | {item.severity} | "
                    f"{item.type} | {item.confidence} | "
                    f"{title} | `{location}` |"
                )

            print()
            print("### Finding details")
            print()

            for item in ordered_findings:
                print(
                    f"**[{item.severity} · {item.type} · "
                    f"{item.confidence}] {item.title}**"
                )
                print()
                print(f"- Evidence: `{item.location}` — {item.evidence}")
                print(f"- Impact: {item.impact}")
                print(f"- Fix: {item.fix}")
                print(f"- Owner: {item.owner}")

                if item.policy:
                    print(f"- Policy: {item.policy}")

                print()
        else:
            print("### Findings")
            print()
            print("Zero mechanical readiness findings.")
            print()

        print("### Security handoff")
        print()

        if result.security_handoffs:
            print("**Required:** Yes")
            print()
            print("| Category | Location | Evidence | Reason |")
            print("|---|---|---|---|")

            for item in result.security_handoffs:
                evidence = item.evidence.replace("|", "\\|")
                reason = item.reason.replace("|", "\\|")

                print(
                    f"| {item.category} | `{item.location}` | "
                    f"{evidence} | {reason} |"
                )

            print()
            print(
                "**Recommended next step:** "
                "Run `skill-security-auditor` against the complete skill directory."
            )
        else:
            print("**Required:** No observed mechanical handoff signal.")
            print()
            print(
                "A separate security review is still required before treating "
                "the skill as safe to install."
            )

        print()
        print("### Semantic checks still required")
        print()

        for check in result.semantic_checks_required:
            print(f"- {check}")

        print()
        print("### Skipped checks")
        print()
        print("| Check | Reason |")
        print("|---|---|")

        for skipped in result.skipped_checks:
            print(
                f"| {skipped['check']} | "
                f"{skipped['reason']} |"
            )

        print()
        print(
            "Security certification: "
            "Not performed by skill-readiness-auditor."
        )
        print()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run deterministic mechanical readiness checks "
            "against one Agent Skill or a skills repository."
        )
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="SKILL.md, skill directory, or repository root",
    )

    parser.add_argument(
        "--target",
        choices=("skill", "repo"),
        default=None,
        help="Force single-skill or repository discovery mode",
    )

    parser.add_argument(
        "--depth",
        choices=("quick", "standard", "deep"),
        default="standard",
        help="Requested semantic review depth",
    )

    parser.add_argument(
        "--model",
        choices=tuple(sorted(VALID_PROFILES)),
        default=None,
        help="Override the readiness model profile",
    )

    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Alias for --format json",
    )

    parser.add_argument(
        "--semantic-complete",
        action="store_true",
        help="Attest that semantic instruction and trigger reviews have been completed",
    )

    return parser.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    arguments = parse_arguments()
    output_format = (
        "json"
        if arguments.json
        else arguments.format
    )

    requested_path = Path(arguments.path)

    try:
        targets, target_root = discover_targets(
            requested_path,
            arguments.target,
        )
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    results = [
        audit_target(
            skill_md=target,
            requested_root=target_root,
            depth=arguments.depth,
            requested_profile=arguments.model,
            semantic_complete=arguments.semantic_complete,
        )
        for target in targets
    ]

    if output_format == "json":
        payload = {
            "schemaVersion": "1.0.0",
            "auditor": "skill-readiness-auditor",
            "auditorVersion": VERSION,
            "targetRoot": str(target_root),
            "targetCount": len(results),
            "semanticBatchLimit": 5,
            "semanticReviewComplete": (
                all(r.semantic_review_complete for r in results)
                if results
                else False
            ),
            "results": [
                result_to_dict(result)
                for result in results
            ],
            "securityCertification": (
                "Not performed by skill-readiness-auditor."
            ),
        }

        print(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_markdown(results, target_root)

    has_blocking_findings = any(
        item.severity in {"Blocker", "Major"}
        for result in results
        for item in result.findings
    )

    return 1 if has_blocking_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
