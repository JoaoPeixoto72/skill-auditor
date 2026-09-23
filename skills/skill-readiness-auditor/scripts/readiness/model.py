"""Vocabulary of the audit: constants, finding records and the verdict they add up to."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Sequence


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

PLUGIN_MANIFESTS = ("plugin.json", ".claude-plugin/plugin.json")


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
