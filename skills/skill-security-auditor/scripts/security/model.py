"""Vocabulary of the audit: constants, the finding record and how one is added."""

from __future__ import annotations

from dataclasses import asdict, dataclass


VERSION = "1.0.0"

# Kept identical to skill-readiness-auditor's EXCLUDED_DIRECTORIES so that both
# audits describe the same target. skill-release-gate combines their reports and
# assumes one target identity.
#
# `tests` is deliberately absent: a payload placed in a test directory must be
# inspected. Only declared security fixtures are excluded, per SKILL.md
# "Target discovery".
EXCLUDED = {
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
    ".md", ".txt", ".json", ".jsonc", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".py", ".sh",
    ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
    ".tsx", ".jsx", ".ps1", ".rb", ".pl", ".php",
    ".xml", ".html",
}

# Extensions whose content an agent or shell can execute. Documentation-context
# suppression never applies to these: prose cannot run, code can.
CODE_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".jsx", ".ps1", ".rb", ".pl", ".php",
}

# Extensions where a security-sensitive phrase may legitimately appear as
# policy prose, a detector specification, or a negated capability declaration.
PROSE_EXTENSIONS = {
    ".md", ".txt", ".json", ".jsonc", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf",
}

# JSON and YAML keys whose value is a specification or documentation pointer,
# never a destination the skill fetches at runtime.
DOC_URL_KEYS = {
    "$schema", "$id", "schema", "docs", "doc", "documentation",
    "homepage", "repository", "url_docs", "reference", "references",
    "seealso", "see_also", "spec", "specification", "license", "licence",
}

DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Pipfile",
    "Pipfile.lock",
    "Cargo.toml",
    "Cargo.lock",
}

SEVERITY_WEIGHT = {
    "Blocker": 4,
    "Major": 3,
    "Minor": 2,
    "Nit": 1,
}


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
    owner: str
    source: str
    rule: str


def clean(value: str, limit: int = 300) -> str:
    value = " ".join(value.strip().split())
    return value if len(value) <= limit else value[:limit - 3] + "..."


def add_finding(
    findings: list[Finding],
    severity: str,
    title: str,
    location: str,
    evidence: str,
    impact: str,
    fix: str,
    rule: str,
    *,
    type_: str = "Security",
    confidence: str = "Observed",
    source: str = "Project policy",
) -> None:
    findings.append(Finding(
        severity=severity,
        type=type_,
        confidence=confidence,
        title=title,
        location=location,
        evidence=clean(evidence),
        impact=impact,
        fix=fix,
        owner="Security",
        source=source,
        rule=rule,
    ))
