#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detectors import (  # noqa: E402
    AUDIT_DECEPTION_RE,
    CONCEALMENT_RE,
    OVERRIDE_RE,
    TRIGGER_HIJACK_RE,
    description_of,
    first_invisible,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


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

def strip_fenced_code(text: str) -> str:
    """Replace content inside fenced markdown code blocks with blank lines to preserve line numbers."""
    def repl(m: re.Match[str]) -> str:
        return "\n" * m.group(0).count("\n")
    return re.sub(r"```[^\n]*\n.*?```", repl, text, flags=re.DOTALL)


def fenced_code_spans(text: str) -> list[tuple[int, int, str]]:
    """Character ranges of fenced markdown code blocks, with their info string."""
    spans: list[tuple[int, int, str]] = []

    for match in re.finditer(
        r"```([^\n]*)\n.*?```",
        text,
        flags=re.DOTALL,
    ):
        start, end = match.span()
        spans.append((start, end, match.group(1).strip().lower()))

    return spans


# Fence languages whose content an agent or shell can execute. A ```text or
# ```json block in a policy document is an illustration, not behavior.
EXECUTABLE_FENCE_LANGUAGES = {
    "bash", "sh", "shell", "zsh", "console", "powershell", "ps1", "pwsh",
    "python", "py", "js", "javascript", "ts", "typescript", "node",
    "ruby", "rb", "perl", "php",
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

# Negation inverts the sentence that contains it: "the skill does not modify
# the Trust Registry" is not a mutation claim. An author gains nothing by
# writing it falsely, so it may appear on the matched line itself.
NEGATION_RE = re.compile(
    r"\b(?:cannot|can\s+not|can't|must\s+not|may\s+not|will\s+not|won't|"
    r"shall\s+not|should\s+not|do\s+not|does\s+not|did\s+not|don't|doesn't|"
    r"never|no\s+longer|without|forbidden|prohibited|disallow\w*|"
    r"not\s+permitted|not\s+allowed|refuse\w*|denies|denied|deny|"
    r"non-?goals?)\b",
    re.I,
)

# Exemplification only frames the text around it. "For example, <payload>" is
# an assertion an attacker can make for free, so it counts only when it comes
# from the list lead-in or the section heading — structure the payload line
# cannot forge on its own.
EXEMPLIFICATION_RE = re.compile(
    r"\b(?:detect\w*|indicator\w*|"
    r"example\w*|counter-?example\w*|fixture\w*|illustrat\w*|sample\w*|"
    r"attempts?\s+to|attempting\s+to|untrusted|"
    r"review\w*\s+for|inspect\w*\s+for|check\w*\s+for)\b",
    re.I,
)

# A structured declaration that switches a capability off, for example
# `target-may-disable-runtime-gate: false` in instruments.yaml.
NEGATED_DECLARATION_RE = re.compile(
    r"^\s*(?:-\s*)?[\"']?[\w.$-]+[\"']?\s*[:=]\s*"
    r"[\"']?(?:false|no|none|never|off|0|denied|blocked|forbidden)[\"']?\s*,?\s*$",
    re.I,
)

LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.*)$")

# JSON and YAML keys whose value is a specification or documentation pointer,
# never a destination the skill fetches at runtime.
DOC_URL_KEYS = {
    "$schema", "$id", "schema", "docs", "doc", "documentation",
    "homepage", "repository", "url_docs", "reference", "references",
    "seealso", "see_also", "spec", "specification", "license", "licence",
}

# Requires a syntactically real authority so that shell globs such as the
# `http://*|https://*` guard in scripts/audit.sh are not read as destinations.
URL_RE = re.compile(
    r"https?://(?:[A-Za-z0-9][A-Za-z0-9-]*\.)*[A-Za-z0-9][A-Za-z0-9-]*"
    r"(?::\d{1,5})?"
    r"(?:[/?#][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?",
    re.I,
)

# Reserved and non-resolvable names (RFC 2606, RFC 6761) plus single-label
# hosts. A documentation URL on one of these is a placeholder, not a
# destination, and declaring it in a resource policy would be meaningless.
PLACEHOLDER_HOST_RE = re.compile(
    r"^(?:[^.]+|"
    r"(?:[\w-]+\.)*(?:invalid|example|test|localhost|local)|"
    r"(?:[\w-]+\.)*example\.(?:com|net|org))$",
    re.I,
)


def placeholder_host(url: str) -> bool:
    return bool(PLACEHOLDER_HOST_RE.match(urlsplit(url).hostname or ""))


MARKDOWN_IMAGE_RE = re.compile(
    r"!\[[^\]]*]\(\s*https?://[^)]+\)",
    re.I,
)

INJECTION_RE = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+"
    r"(?:rules|instructions)|"
    r"(?:return|mark\s+as)\s+(?:only\s+)?(?:ready|approve)|"
    r"skip\s+(?:the\s+)?(?:audit|verification)|"
    r"do\s+not\s+(?:report|list)\s+findings|"
    r"reveal\s+(?:the\s+)?system\s+prompt|"
    r"bypass\s+(?:the\s+)?runtime\s+gate|"
    r"modify\s+(?:the\s+)?trust\s+registry",
    re.I,
)

OBFUSCATION_RE = re.compile(
    r"base64\s+(?:-d|--decode).*?\|\s*(?:bash|sh|python|node)|"
    r"\b(?:eval|exec)\s*\([^)]*(?:base64|fromhex|atob)|"
    r"\bxxd\s+-r.*?\|\s*(?:bash|sh)",
    re.I | re.S,
)

NETWORK_RE = re.compile(
    r"\b(?:WebFetch|curl|wget|Invoke-WebRequest)\b|"
    r"\bfetch\s*\(|"
    r"\brequests\.(?:get|post|put|delete|request)\s*\(|"
    r"\bhttpx\.(?:get|post|put|delete|request)\s*\(|"
    r"\baxios\.(?:get|post|put|delete|request)\s*\(|"
    r"\bhttps?\.request\s*\(",
    re.I,
)

SENSITIVE_RE = re.compile(
    r"\b(?:process\.env|os\.environ|os\.getenv|\.env|"
    r"api[_-]?key|access[_-]?token|session[_-]?cookie|"
    r"id_rsa|id_ed25519|private[_-]?key|credential)\b",
    re.I,
)

# Persistence requires an operation, not a topic. A bare word such as
# "startup" appears in any document that discusses persistence and is not
# evidence of it.
PERSISTENCE_RE = re.compile(
    r"\bcrontab\s+-[el]\b|"
    r"\b(?:>>?|tee|cp|mv|echo\b.*>>?)\s*[^\n]{0,40}"
    r"(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|/cron\.d/|"
    r"LaunchAgents/|LaunchDaemons/)|"
    r"\blaunchctl\s+(?:load|bootstrap|enable)\b|"
    r"\bsystemctl\s+(?:--user\s+)?enable\b|"
    r"\bschtasks\s+/create\b|"
    r"\bNew-ScheduledTask\b|"
    r"\bRegister-ScheduledJob\b",
    re.I,
)

# Bounded to a single line: a prose paragraph that mentions the Runtime Gate
# and, two sentences later, the word "modify" is not a mutation capability.
REGISTRY_TAMPER_RE = re.compile(
    r"(?:write|edit|modify|replace|delete|reset|clear)[^\n]{0,60}?"
    r"(?:trust[- ]registry|runtime[- ]gate)|"
    r"(?:trust[- ]registry|runtime[- ]gate)[^\n]{0,60}?"
    r"(?:write|edit|modify|replace|delete|reset|clear)",
    re.I,
)

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

MUTABLE_DEPENDENCY_RE = re.compile(
    r"(?:git\+https?://|https?://).{0,200}"
    r"(?:@main|@master|/main/|/master/|/latest/)|"
    r"\b(?:pip|npm|pnpm|yarn|uv).{0,80}(?:install|add)\s+"
    r"[A-Za-z0-9_.@/-]+(?:\s|$)",
    re.I,
)

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


def excluded(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part in EXCLUDED for part in relative.parts)


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


def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and not excluded(path, root):
            yield path


def iter_text_files(root: Path) -> Iterable[tuple[Path, str]]:
    for path in iter_files(root):
        if path.name == "SKILL.md" or path.suffix.lower() in TEXT_EXTENSIONS:
            text = read_text(path)
            if text is not None:
                yield path, text


def line_location(path: Path, text: str, needle: str) -> str:
    index = text.find(needle)
    if index < 0:
        return str(path)
    return f"{path}:{text.count(chr(10), 0, index) + 1}"


def line_index_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset)


def enclosing_clause(text: str, offset: int) -> tuple[str, str]:
    """Return the clause and the section heading surrounding a match.

    A prohibition is usually written as a lead-in sentence followed by a bullet
    list, for example:

        A target skill cannot:
        - change Trust Registry state;

    The bullet alone reads as a capability. The clause therefore spans the
    matched line plus the lead-in line that introduces the enclosing list.
    """
    lines = text.splitlines()
    index = min(line_index_at(text, offset), max(len(lines) - 1, 0))

    if not lines:
        return "", ""

    clause = [lines[index]]

    if LIST_ITEM_RE.match(lines[index]):
        cursor = index - 1
        while cursor >= 0:
            candidate = lines[cursor]
            if LIST_ITEM_RE.match(candidate) or not candidate.strip():
                cursor -= 1
                continue
            clause.insert(0, candidate)
            break

    heading = ""
    cursor = index
    while cursor >= 0:
        match = HEADING_RE.match(lines[cursor])
        if match:
            heading = match.group(1)
            break
        cursor -= 1

    return "\n".join(clause), heading


def pattern_definition_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges of module-level detector constants in Python source.

    A security scanner necessarily contains the strings it looks for. Matching a
    scanner's own `INJECTION_RE = re.compile(...)` is a self-match, not target
    behavior. Only ALL-CAPS module-level constants qualify, and the match is
    still reported as a documentation-context match rather than dropped.
    """
    spans: list[tuple[int, int]] = []
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    cursor = 0

    for line in lines:
        offsets.append(cursor)
        cursor += len(line)

    # Parentheses inside regex literals make brace counting unreliable, so the
    # span ends at the first closing delimiter written in column 0 — the layout
    # this file and every sibling script uses for module constants.
    for index, line in enumerate(lines):
        if not re.match(r"^[A-Z][A-Z0-9_]*\s*=\s*(?:re\.compile\(|\{|\()", line):
            continue

        stripped = line.rstrip().rstrip(",")

        if stripped.endswith((")", "}")):
            spans.append((offsets[index], offsets[index] + len(line)))
            continue

        for lookahead in range(index + 1, min(index + 80, len(lines))):
            if re.match(r"^[)}],?\s*$", lines[lookahead]):
                spans.append(
                    (offsets[index], offsets[lookahead] + len(lines[lookahead]))
                )
                break

    return spans


def enclosing_fence(
    start: int,
    code_spans: list[tuple[int, int, str]],
) -> tuple[bool, str]:
    for span_start, span_end, language in code_spans:
        if span_start <= start < span_end:
            return True, language
    return False, ""


def documentation_context(
    path: Path,
    text: str,
    start: int,
    end: int,
    code_spans: list[tuple[int, int, str]],
    pattern_spans: list[tuple[int, int]],
    honour_negation: bool = True,
) -> str | None:
    """Explain why a match is documentation rather than behavior, or return None.

    `honour_negation=False` is for detectors whose payload is itself a
    negation (concealment from the user): the sentence cannot exonerate itself.

    Suppression is reported, never silent: the caller records every suppressed
    match in `documentationMatches`.
    """
    suffix = path.suffix.lower()

    if any(
        span_start <= start and end <= span_end
        for span_start, span_end in pattern_spans
    ):
        return "detector pattern definition"

    if suffix in CODE_EXTENSIONS or suffix not in PROSE_EXTENSIONS:
        return None

    fenced, language = enclosing_fence(start, code_spans)

    if fenced and language not in EXECUTABLE_FENCE_LANGUAGES:
        return f"illustration in a non-executable ```{language or 'plain'} block"

    # The matched text is masked out of every window: a payload must not
    # qualify as its own exoneration by containing a word such as "rules".
    clause, heading = enclosing_clause(text, start)
    tail_clause, _ = enclosing_clause(text, max(end - 1, start))
    window = clause if tail_clause == clause else f"{clause}\n{tail_clause}"
    masked = window.replace(text[start:end], " ")

    lines = clause.splitlines()

    if honour_negation and lines and NEGATED_DECLARATION_RE.match(lines[-1]):
        return "negated capability declaration"

    if honour_negation and NEGATION_RE.search(masked):
        return "negated statement in the enclosing clause"

    # Structural framing only: the list lead-in, never the matched line.
    lead_in = "\n".join(lines[:-1]) if len(lines) > 1 else ""

    if lead_in and EXEMPLIFICATION_RE.search(lead_in):
        return "example introduced by the enclosing list lead-in"

    if heading and (
        (honour_negation and NEGATION_RE.search(heading))
        or EXEMPLIFICATION_RE.search(heading)
    ):
        return f"prohibition or example section: {clean(heading, 80)}"

    return None


def discover(target: Path, mode: str | None) -> list[Path]:
    target = target.resolve()

    if target.is_file():
        if target.name != "SKILL.md":
            raise ValueError("File target must be named SKILL.md")
        return [target.parent]

    if not target.is_dir():
        raise ValueError(f"Target does not exist: {target}")

    if (target / "SKILL.md").is_file() and mode != "repo":
        return [target]

    if mode == "skill":
        raise ValueError("--target skill requires a skill directory")

    results = []
    for skill_md in sorted(target.rglob("SKILL.md")):
        if excluded(skill_md, target):
            continue
        results.append(skill_md.parent)

    if not results:
        raise ValueError(f"No skills found under {target}")

    return results


def canonical_url(value: str) -> str:
    value = value.rstrip(".,;:)'\"`")
    parsed = urlsplit(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        return value

    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    netloc = host + port

    if parsed.username or parsed.password:
        user = parsed.username or ""
        netloc = f"{user}@{netloc}"

    return urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))


def load_manifest(
    skill_dir: Path,
    findings: list[Finding],
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    path = skill_dir / "external-resources.json"

    if not path.exists():
        return None, {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        add_finding(
            findings,
            "Blocker",
            "Invalid external-resource manifest",
            str(path),
            str(error),
            "The runtime cannot derive an enforceable resource policy.",
            "Replace it with valid JSON.",
            "§20",
        )
        return None, {}

    required = {
        "version",
        "hasExternalResources",
        "requiresRuntimeGate",
        "resources",
    }

    if not isinstance(data, dict) or not required.issubset(data):
        add_finding(
            findings,
            "Major",
            "Incomplete external-resource manifest",
            str(path),
            f"Required fields: {sorted(required)}",
            "Resource and Runtime Gate state cannot be established.",
            "Add all required fields.",
            "§20",
        )
        return data if isinstance(data, dict) else None, {}

    resources = data.get("resources")

    if not isinstance(resources, list):
        add_finding(
            findings,
            "Blocker",
            "Resource declaration is not an array",
            str(path),
            repr(resources),
            "The resource allowlist cannot be processed.",
            "Set resources to an array.",
            "§20",
        )
        return data, {}

    declared: dict[str, dict[str, Any]] = {}

    for index, resource in enumerate(resources):
        location = f"{path}:resources[{index}]"

        if not isinstance(resource, dict):
            add_finding(
                findings,
                "Blocker",
                "Invalid external-resource entry",
                location,
                repr(resource),
                "The entry cannot be enforced.",
                "Replace it with an object.",
                "§20",
            )
            continue

        url = resource.get("url")
        tier = resource.get("tier")
        purpose = resource.get("purpose")
        max_bytes = resource.get("maxBytes")

        if not isinstance(url, str):
            add_finding(
                findings,
                "Blocker",
                "External resource has no valid URL",
                location,
                repr(url),
                "The destination cannot be authorized.",
                "Declare an exact HTTPS URL.",
                "§21",
            )
            continue

        normalized = canonical_url(url)

        if not normalized.startswith("https://"):
            add_finding(
                findings,
                "Blocker",
                "Runtime URL is not HTTPS",
                location,
                normalized,
                "The resource lacks transport confidentiality and integrity.",
                "Use an exact HTTPS URL.",
                "§21",
            )

        if "@" in urlsplit(url).netloc:
            add_finding(
                findings,
                "Blocker",
                "URL contains embedded credentials",
                location,
                normalized,
                "Credentials may leak through configuration or logs.",
                "Remove URL credentials.",
                "§21",
            )

        if tier not in {0, 1, 2, 3}:
            add_finding(
                findings,
                "Blocker",
                "Unknown external-resource tier",
                location,
                repr(tier),
                "The Runtime Gate cannot select a safe policy.",
                "Use Tier 0, 1, 2, or 3.",
                "§20",
            )

        if not isinstance(purpose, str) or len(purpose.strip()) < 3:
            add_finding(
                findings,
                "Major",
                "External resource has no meaningful purpose",
                location,
                repr(purpose),
                "Reviewers cannot determine whether access is necessary.",
                "Document the bounded purpose.",
                "§20",
            )

        if (
            not isinstance(max_bytes, int)
            or max_bytes < 1
            or max_bytes > 10_485_760
        ):
            add_finding(
                findings,
                "Major",
                "Invalid external response limit",
                location,
                repr(max_bytes),
                "The runtime may accept unbounded remote content.",
                "Set maxBytes between 1 and 10485760.",
                "§29",
            )

        if tier == 1 and not re.fullmatch(
            r"sha256-[a-fA-F0-9]{64}",
            str(resource.get("hash", "")),
        ):
            add_finding(
                findings,
                "Blocker",
                "Tier 1 resource lacks a valid SHA-256 pin",
                location,
                repr(resource.get("hash")),
                "Post-audit remote mutation cannot be detected.",
                "Add a byte-level SHA-256 pin.",
                "§23",
            )

        if tier == 2:
            schema = resource.get("schema")
            if (
                not isinstance(schema, dict)
                or schema.get("type") != "object"
                or not isinstance(schema.get("allowedKeys"), list)
            ):
                add_finding(
                    findings,
                    "Blocker",
                    "Tier 2 resource lacks a strict schema",
                    location,
                    repr(schema),
                    "Dynamic content may reach the agent without bounded structure.",
                    "Declare an object schema with allowedKeys.",
                    "§24",
                )

        if tier == 3:
            missing = [
                key for key in (
                    "keyId",
                    "signatureHeader",
                    "enterpriseAuthorization",
                )
                if not resource.get(key)
            ]
            if missing:
                add_finding(
                    findings,
                    "Blocker",
                    "Tier 3 resource lacks managed trust controls",
                    location,
                    f"Missing: {missing}",
                    "Agent-controlling content cannot be authenticated.",
                    "Add managed authorization and trusted-key references.",
                    "§25",
                )

        if normalized in declared:
            add_finding(
                findings,
                "Major",
                "Duplicate external-resource declaration",
                location,
                normalized,
                "Multiple policies may compete for one destination.",
                "Keep one declaration per normalized URL.",
                "§20",
            )
        else:
            declared[normalized] = resource

    return data, declared


def url_usage(
    path: Path,
    text: str,
    offset: int,
    code_spans: list[tuple[int, int, str]],
) -> str:
    """Classify one URL occurrence as `runtime` or `documentation`.

    Only a runtime occurrence can produce an actual request, so only a runtime
    occurrence needs an entry in external-resources.json. A documentation
    occurrence is a Tier 0 candidate: human-readable, never fetched.
    """
    suffix = path.suffix.lower()

    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    line = text[line_start:line_end if line_end >= 0 else len(text)]

    # A specification identifier such as `$schema` names a document, it does
    # not request one. The key may sit on the line above the value.
    preceding = text[:line_start].rstrip().rsplit("\n", 1)[-1] if line_start else ""

    for candidate in (line, preceding):
        key = re.match(r"\s*[\"']?([\w.$-]+)[\"']?\s*[:=]", candidate)
        if key and key.group(1).lower() in DOC_URL_KEYS:
            return "documentation"

    if suffix in CODE_EXTENSIONS:
        return "runtime"

    if NETWORK_RE.search(line):
        return "runtime"

    if suffix == ".md":
        fenced, language = enclosing_fence(offset, code_spans)
        return (
            "runtime"
            if fenced and language in EXECUTABLE_FENCE_LANGUAGES
            else "documentation"
        )

    if suffix in {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return "runtime"

    return "documentation"


# A network tool granted in frontmatter is a capability. The same name under
# `disallowed-tools` is the opposite claim and must not count.
ALLOWED_TOOLS_RE = re.compile(
    r"^allowed-tools:\s*(.*?)(?=^\S|\Z)",
    re.M | re.S,
)


def declares_network_tool(text: str) -> bool:
    match = ALLOWED_TOOLS_RE.search(text)
    return bool(match and NETWORK_RE.search(match.group(1)))


def comment_and_docstring_spans(text: str, suffix: str) -> list[tuple[int, int]]:
    """Character ranges of source text that never executes.

    Used for capability detection only. A payload written in a comment is still
    reported as a finding, because an agent reads the whole file; it is simply
    not evidence that the file performs a network call.
    """
    spans: list[tuple[int, int]] = []

    if suffix == ".py":
        for match in re.finditer(r'"""(?:.|\n)*?"""|\'\'\'(?:.|\n)*?\'\'\'', text):
            spans.append(match.span())

    comment = {
        ".py": r"#[^\n]*",
        ".sh": r"#[^\n]*",
        ".bash": r"#[^\n]*",
        ".zsh": r"#[^\n]*",
        ".rb": r"#[^\n]*",
        ".pl": r"#[^\n]*",
        ".ps1": r"#[^\n]*",
    }.get(suffix, r"//[^\n]*|/\*(?:.|\n)*?\*/")

    for match in re.finditer(comment, text):
        spans.append(match.span())

    return spans


def observes_network_call(
    path: Path,
    text: str,
    pattern_spans: list[tuple[int, int]],
    code_spans: list[tuple[int, int, str]],
) -> bool:
    """True when a file that executes contains a real network call.

    Prose that names `curl` or `WebFetch`, and a scanner's own detector
    pattern, are not network capability. A command inside an executable fenced
    block is: the skill instructs an agent to run it.
    """
    if path.name == "SKILL.md" and declares_network_tool(text):
        return True

    if path.suffix.lower() == ".md":
        return any(
            language in EXECUTABLE_FENCE_LANGUAGES
            and NETWORK_RE.search(text[start:end])
            for start, end, language in code_spans
        )

    suffix = path.suffix.lower()

    if suffix not in CODE_EXTENSIONS:
        return False

    inert = pattern_spans + comment_and_docstring_spans(text, suffix)

    return any(
        not any(
            span_start <= match.start() and match.end() <= span_end
            for span_start, span_end in inert
        )
        for match in NETWORK_RE.finditer(text)
    )


def scan_skill(
    skill_dir: Path,
    strict: bool,
    runtime_attestation: Path | None,
) -> dict[str, Any]:
    findings: list[Finding] = []
    doc_matches: list[dict[str, str]] = []
    observed_urls: dict[str, list[str]] = {}
    url_usages: dict[str, set[str]] = {}
    network_capable = False
    file_count = 0
    text_count = 0
    binary_files: list[str] = []
    dependencies: list[str] = []

    for path in iter_files(skill_dir):
        file_count += 1
        relative = path.relative_to(skill_dir).as_posix()

        if path.name in DEPENDENCY_FILES:
            dependencies.append(relative)

        text = read_text(path)

        if text is None:
            binary_files.append(relative)
            continue

        text_count += 1

        code_spans = (
            fenced_code_spans(text) if path.suffix.lower() == ".md" else []
        )
        pattern_spans = (
            pattern_definition_spans(text)
            if path.suffix.lower() == ".py"
            else []
        )

        def record(
            match: re.Match[str] | None,
            severity: str,
            title: str,
            impact: str,
            fix: str,
            rule: str,
            *,
            confidence: str = "Observed",
            location: str | None = None,
            honour_negation: bool = True,
        ) -> None:
            """Add a finding, or record the match as documentation context.

            Nothing is dropped. A suppressed match stays visible in the report
            under "Documentation-context matches" so a reviewer can audit the
            suppression itself.
            """
            if match is None:
                return

            where = location or line_location(
                Path(relative), text, match.group(0)
            )
            reason = documentation_context(
                path,
                text,
                match.start(),
                match.end(),
                code_spans,
                pattern_spans,
                honour_negation,
            )

            if reason is not None:
                doc_matches.append({
                    "title": title,
                    "location": where,
                    "evidence": clean(match.group(0)),
                    "reason": reason,
                    "rule": rule,
                })
                return

            add_finding(
                findings,
                severity,
                title,
                where,
                match.group(0),
                impact,
                fix,
                rule,
                confidence=confidence,
            )

        if path.name != "external-resources.json":
            for match in URL_RE.finditer(text):
                normalized = canonical_url(match.group(0))
                observed_urls.setdefault(normalized, []).append(
                    line_location(Path(relative), text, match.group(0))
                )
                url_usages.setdefault(normalized, set()).add(
                    url_usage(path, text, match.start(), code_spans)
                )

        invisible = first_invisible(text)
        if invisible is not None:
            offset, point = invisible
            add_finding(
                findings,
                "Blocker",
                "Invisible or bidirectional Unicode detected",
                f"{relative}:{line_index_at(text, offset) + 1}",
                f"Unicode U+{point:04X}",
                "Hidden or reordered instructions may evade review.",
                "Remove the character and review surrounding content.",
                "§9",
            )

        record(
            INJECTION_RE.search(text),
            "Blocker",
            "Prompt-injection indicator detected",
            "The target attempts to influence an agent or its own audit.",
            "Remove the directive and investigate the source.",
            "§8",
        )

        record(
            OVERRIDE_RE.search(text),
            "Blocker",
            "Instruction-override directive detected",
            "The target tells the agent to discard its instructions, in any language.",
            "Remove the directive and investigate the source.",
            "§8",
        )

        record(
            CONCEALMENT_RE.search(text),
            "Blocker",
            "Instruction to conceal behaviour from the user",
            "The agent is told to act without the user's knowledge.",
            "Remove the directive; a skill never hides a step from its user.",
            "§8",
            honour_negation=False,
        )

        record(
            AUDIT_DECEPTION_RE.search(text),
            "Blocker",
            "Instruction to deceive an auditor",
            "The target scripts its own answer to review, which is deceptive by design.",
            "Reject the skill and investigate its source.",
            "§8",
            honour_negation=False,
        )

        if path.name == "SKILL.md":
            described = description_of(text)
            hijack = TRIGGER_HIJACK_RE.search(described[0]) if described else None
            if hijack:
                add_finding(
                    findings,
                    "Major",
                    "Description claims every request",
                    line_location(Path(relative), text, hijack.group(0)),
                    hijack.group(0),
                    "Routing would load the skill for unrelated work, widening its reach.",
                    "Describe the specific tasks and moments the skill is for.",
                    "§8",
                )

        record(
            OBFUSCATION_RE.search(text),
            "Blocker",
            "Encoded or obfuscated execution detected",
            "Executed behavior is concealed from ordinary review.",
            "Replace it with transparent source or reject the skill.",
            "§10",
        )

        record(
            MARKDOWN_IMAGE_RE.search(text),
            "Major",
            "External Markdown image detected",
            "Rendering may create an undeclared external request.",
            "Vendor the image locally or remove it.",
            "§15",
        )

        if observes_network_call(path, text, pattern_spans, code_spans):
            network_capable = True

        # Co-occurrence of a sensitive read and a network call is only evidence
        # of a data flow in a file that executes. In prose, both are topics.
        if path.suffix.lower() in CODE_EXTENSIONS:
            sensitive = SENSITIVE_RE.search(text)
            network = NETWORK_RE.search(text)

            if sensitive and network:
                suppressed = documentation_context(
                    path,
                    text,
                    sensitive.start(),
                    sensitive.end(),
                    code_spans,
                    pattern_spans,
                ) and documentation_context(
                    path,
                    text,
                    network.start(),
                    network.end(),
                    code_spans,
                    pattern_spans,
                )

                if suppressed:
                    doc_matches.append({
                        "title": "Sensitive-data access and network behavior coexist",
                        "location": str(relative),
                        "evidence": clean(
                            f"{sensitive.group(0)}; {network.group(0)}"
                        ),
                        "reason": suppressed,
                        "rule": "§14-§15",
                    })
                else:
                    add_finding(
                        findings,
                        "Major",
                        "Sensitive-data access and network behavior coexist",
                        str(relative),
                        f"{sensitive.group(0)}; {network.group(0)}",
                        "The skill may be capable of transmitting sensitive runtime data.",
                        "Review the data flow and remove or strictly bound one capability.",
                        "§14-§15",
                        confidence="Inferred",
                    )

        record(
            PERSISTENCE_RE.search(text),
            "Major",
            "Persistence-related behavior detected",
            "The skill may affect future sessions or system startup.",
            "Remove persistence or require explicit consent and cleanup.",
            "§16",
            confidence="Inferred",
        )

        record(
            REGISTRY_TAMPER_RE.search(text),
            "Blocker",
            "Trust or Runtime Gate modification detected",
            "The skill may alter its own security boundary.",
            "Remove registry or gate mutation capability.",
            "§17",
        )

        if path.name in DEPENDENCY_FILES:
            record(
                MUTABLE_DEPENDENCY_RE.search(text),
                "Major",
                "Mutable or unpinned dependency source detected",
                "Dependency behavior may change after audit.",
                "Pin an immutable version, digest, or commit.",
                "§18",
            )

    manifest, declared = load_manifest(skill_dir, findings)

    runtime_urls = {
        url
        for url, usages in url_usages.items()
        if "runtime" in usages
    }

    for url, locations in sorted(observed_urls.items()):
        if url in declared:
            continue

        if url not in runtime_urls:
            if placeholder_host(url):
                doc_matches.append({
                    "title": "Undeclared documentation URL",
                    "location": locations[0],
                    "evidence": clean(url),
                    "reason": "reserved or single-label placeholder host",
                    "rule": "§20",
                })
                continue

            add_finding(
                findings,
                "Minor",
                "Undeclared documentation URL",
                locations[0],
                url,
                "The destination is human-readable only and is not fetched by the "
                "bundle, but it is absent from the resource policy.",
                "Declare it as Tier 0 or accept it as documentation.",
                "§20",
                type_="Concern",
            )
            continue

        add_finding(
            findings,
            "Blocker" if network_capable else "Major",
            (
                "Undeclared runtime-capable external URL"
                if network_capable
                else "Undeclared external URL"
            ),
            locations[0],
            url,
            "The destination is absent from the approved resource policy.",
            "Declare and classify the URL or remove it.",
            "§20",
        )

    for url in sorted(declared):
        if url not in observed_urls:
            add_finding(
                findings,
                "Minor",
                "Stale external-resource allowlist entry",
                str(skill_dir / "external-resources.json"),
                url,
                "The allowlist contains a destination not observed in the bundle.",
                "Remove the entry or document its construction.",
                "§20",
                type_="Concern",
            )

    tiers = {
        value.get("tier")
        for value in declared.values()
        if isinstance(value, dict)
    }
    requires_gate = network_capable or bool(tiers & {1, 2, 3})
    # Tier 0 documentation links are not external resources for policy purposes:
    # nothing in the bundle fetches them. Counting them would force every skill
    # with a reference link to carry a manifest.
    has_external = bool(runtime_urls or declared)

    if manifest is None and has_external:
        add_finding(
            findings,
            "Blocker" if network_capable else "Major",
            "External resources have no declaration manifest",
            str(skill_dir),
            "external-resources.json is absent",
            "The resource policy cannot be enforced.",
            "Create and validate external-resources.json.",
            "§20",
        )

    if manifest is not None:
        if bool(manifest.get("hasExternalResources")) != has_external:
            add_finding(
                findings,
                "Major",
                "hasExternalResources is inconsistent",
                str(skill_dir / "external-resources.json"),
                repr(manifest.get("hasExternalResources")),
                "The machine-readable risk state disagrees with the bundle.",
                f"Set it to {str(has_external).lower()}.",
                "§20",
            )

        if bool(manifest.get("requiresRuntimeGate")) != requires_gate:
            add_finding(
                findings,
                "Blocker" if requires_gate else "Major",
                "requiresRuntimeGate is inconsistent",
                str(skill_dir / "external-resources.json"),
                repr(manifest.get("requiresRuntimeGate")),
                "Network behavior may bypass required runtime controls.",
                f"Set it to {str(requires_gate).lower()}.",
                "§26",
            )

    runtime_status = "NOT_REQUIRED"

    if requires_gate:
        runtime_status = "UNVERIFIED"

        if runtime_attestation and runtime_attestation.is_file():
            try:
                attestation = json.loads(
                    runtime_attestation.read_text(encoding="utf-8")
                )
                required = {
                    "networkInterceptionEnabled": True,
                    "directEgressBlocked": True,
                    "bundleIntegrityEnabled": True,
                    "quarantineRevocationEnabled": True,
                }
                if all(
                    attestation.get(key) == value
                    for key, value in required.items()
                ):
                    runtime_status = "VERIFIED"
            except Exception:
                runtime_status = "UNVERIFIED"

        if strict and runtime_status != "VERIFIED":
            add_finding(
                findings,
                "Major",
                "Runtime Gate enforcement is unverified",
                str(runtime_attestation or "<no-attestation>"),
                runtime_status,
                "A network-capable skill may bypass declared resource policy.",
                "Provide privileged-host runtime enforcement attestation.",
                "§26-§27",
                confidence="Unknown",
            )

    return {
        "skill": str(skill_dir),
        "fileCount": file_count,
        "textFileCount": text_count,
        "binaryFiles": binary_files,
        "dependencyFiles": dependencies,
        "networkCapable": network_capable,
        "hasExternalResources": has_external,
        "requiresRuntimeGate": requires_gate,
        "runtimeEnforcement": runtime_status,
        "observedUrls": observed_urls,
        "urlUsage": {
            url: sorted(usages)
            for url, usages in sorted(url_usages.items())
        },
        "runtimeUrls": sorted(runtime_urls),
        "declaredResources": list(declared.values()),
        "findings": [asdict(item) for item in findings],
        "documentationMatches": doc_matches,
    }


def load_skillspector(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {
            "status": "UNAVAILABLE",
            "completeness": "UNAVAILABLE",
            "findings": [],
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {
            "status": "FAILED",
            "completeness": "FAILED",
            "findings": [],
        }
    except Exception as error:
        return {
            "status": "FAILED",
            "completeness": "FAILED",
            "error": str(error),
            "findings": [],
        }


def load_scanner_trust(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"trust": "UNVERIFIED", "errors": ["No scanner-trust record supplied."]}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        return {"trust": "FAILED", "errors": [f"Unreadable scanner-trust record: {error}"]}

    if not isinstance(data, dict) or "trust" not in data:
        return {"trust": "FAILED", "errors": ["Malformed scanner-trust record."]}

    return data


def scanner_material_severity(finding: dict[str, Any]) -> str:
    value = str(
        finding.get("severity")
        or finding.get("level")
        or finding.get("properties", {}).get("severity", "")
    ).upper()
    return value


def analysis_lines(scanner: dict[str, Any]) -> list[str]:
    """Which independent evidence lines actually ran."""
    lines = ["project-policy"]
    if scanner.get("completeness") not in (None, "UNAVAILABLE", "FAILED"):
        lines.append("skillspector")
    return lines


def decide_verdict(
    project_results: list[dict[str, Any]],
    scanner: dict[str, Any],
    strict: bool,
    scanner_trust: dict[str, Any] | None = None,
    require_scanner: bool = False,
) -> str:
    project_findings = [
        finding
        for result in project_results
        for finding in result["findings"]
    ]
    external_severities = {
        scanner_material_severity(item)
        for item in scanner.get("findings", [])
        if isinstance(item, dict)
    }

    # Evidence of harm rejects whatever the state of the other line: a scanner
    # that cannot be trusted never makes a malicious finding less true.
    if any(finding["severity"] == "Blocker" for finding in project_findings):
        return "Reject"

    if "CRITICAL" in external_severities or scanner.get("recommendation") == "DO_NOT_INSTALL":
        return "Reject"

    if scanner_trust and scanner_trust.get("trust") == "FAILED":
        return "Hold"

    # SkillSpector is optional. Absent, the project-policy line decides alone
    # and the report says so; present, its evidence must be complete.
    completeness = scanner.get("completeness", "UNAVAILABLE")

    if completeness != "UNAVAILABLE" and completeness != "COMPLETE":
        return "Hold"

    if require_scanner and completeness != "COMPLETE":
        return "Hold"

    if any(finding["severity"] == "Major" for finding in project_findings):
        return "Hold"

    if external_severities & {"HIGH", "MEDIUM", "LOW"}:
        return "Hold"

    if not strict:
        return "Hold"

    return "Eligible for enrolment"


def sarif_output(
    results: list[dict[str, Any]],
    scanner: dict[str, Any],
) -> dict[str, Any]:
    sarif_results = []

    for result in results:
        for finding in result["findings"]:
            level = {
                "Blocker": "error",
                "Major": "error",
                "Minor": "warning",
                "Nit": "note",
            }[finding["severity"]]

            sarif_results.append({
                "ruleId": finding["rule"],
                "level": level,
                "message": {
                    "text": finding["title"]
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["location"].split(":")[0]
                        }
                    }
                }],
                "properties": finding,
            })

    return {
        "version": "2.1.0",
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skill-security-auditor",
                    "version": VERSION,
                }
            },
            "results": sarif_results,
            "properties": {
                "skillspector": scanner,
            },
        }],
    }


def print_markdown(payload: dict[str, Any]) -> None:
    print("# Agent Skill Security Audit")
    print()
    print(f"**Security verdict:** {payload['securityVerdict']}  ")
    print(f"**Strict mode:** {str(payload['strict']).lower()}  ")
    print(f"**Analysis mode:** {payload['mode']}  ")
    print(
        f"**SkillSpector:** "
        f"{payload['skillspector']['completeness']}  "
    )
    print(
        f"**SkillSpector version:** "
        f"{payload['skillspector'].get('scannerVersion')}  "
    )
    print(
        f"**Scanner trust:** "
        f"{payload['scannerTrust'].get('trust')}  "
    )
    print(f"**Evidence lines:** {', '.join(payload['analysisLines'])}  ")
    print()

    if payload["mode"] == "semantic":
        print(
            "Semantic review is performed by the auditing model, not by this "
            "script. This report carries the deterministic evidence only."
        )
        print()

    for result in payload["results"]:
        print(f"## {result['skill']}")
        print()
        print(f"- Files discovered: {result['fileCount']}")
        print(f"- Text files inspected: {result['textFileCount']}")
        print(f"- Network capable: `{str(result['networkCapable']).lower()}`")
        print(
            f"- Has external resources: "
            f"`{str(result['hasExternalResources']).lower()}`"
        )
        print(
            f"- Requires Runtime Gate: "
            f"`{str(result['requiresRuntimeGate']).lower()}`"
        )
        print(
            f"- Runtime enforcement: "
            f"`{result['runtimeEnforcement']}`"
        )
        print()

        findings = result["findings"]

        if findings:
            print("### Project-policy findings")
            print()
            for finding in findings:
                print(
                    f"**[{finding['severity']} · {finding['type']} · "
                    f"{finding['confidence']}] {finding['title']}**"
                )
                print(f"- Evidence: `{finding['location']}` — {finding['evidence']}")
                print(f"- Impact: {finding['impact']}")
                print(f"- Fix: {finding['fix']}")
                print(f"- Rule: {finding['rule']}")
                print()
        else:
            print("Zero project-policy findings.")
            print()

        doc_matches = result.get("documentationMatches", [])

        if doc_matches:
            print(
                f"### Documentation-context matches "
                f"({len(doc_matches)}, not findings)"
            )
            print()
            print(
                "Security-sensitive phrases that the enclosing prose negates, "
                "prohibits, or specifies as a detector. Review the suppression "
                "itself if the target is untrusted."
            )
            print()
            print("| Rule | Location | Evidence | Why not a finding |")
            print("|---|---|---|---|")
            for item in doc_matches:
                evidence = item["evidence"].replace("|", "\\|")
                print(
                    f"| {item['rule']} | `{item['location']}` | "
                    f"{evidence} | {item['reason']} |"
                )
            print()

    scanner_findings = payload["skillspector"].get("findings", [])
    print(f"## SkillSpector findings ({len(scanner_findings)})")
    print()

    for finding in scanner_findings:
        print(f"- `{json.dumps(finding, ensure_ascii=False)}`")

    if not scanner_findings:
        print("No normalized SkillSpector findings.")

    print()
    print("## Safety record")
    print()
    print("- Target files modified: no")
    print("- Target scripts executed: no")
    print("- Target URLs fetched: no")
    print("- Dependencies installed: no")
    print("- Trust Registry modified: no")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Path to local skill directory, SKILL.md, or repository")
    parser.add_argument(
        "--target-mode",
        dest="target_mode",
        choices=("skill", "repo"),
        help="Target discovery mode",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--mode",
        choices=("static", "semantic"),
        default="static",
        help=(
            "Requested analysis mode. This script is always deterministic and "
            "local; `semantic` records that the operator authorized the model "
            "to perform the additional semantic review described in SKILL.md."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "sarif"),
        default="markdown",
    )
    parser.add_argument("--skillspector-report")
    parser.add_argument(
        "--scanner-trust",
        dest="scanner_trust",
        help="Path to the scanner-trust record from verify-skillspector.py",
    )
    parser.add_argument("--runtime-attestation")
    parser.add_argument(
        "--require-scanner",
        action="store_true",
        help="Hold unless SkillSpector ran completely (two evidence lines).",
    )
    args = parser.parse_args()

    target_value = args.target

    if re.match(r"^(?:https?|git|ssh)://", target_value, re.I):
        print("Error: only local targets are accepted.", file=sys.stderr)
        return 2

    try:
        skill_directories = discover(
            Path(target_value),
            args.target_mode,
        )
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    runtime_attestation = (
        Path(args.runtime_attestation).resolve()
        if args.runtime_attestation
        else None
    )

    results = [
        scan_skill(
            skill_dir,
            args.strict,
            runtime_attestation,
        )
        for skill_dir in skill_directories
    ]

    scanner = load_skillspector(
        Path(args.skillspector_report)
        if args.skillspector_report
        else None
    )

    scanner_trust = load_scanner_trust(
        Path(args.scanner_trust) if args.scanner_trust else None
    )

    verdict = decide_verdict(
        results,
        scanner,
        args.strict,
        scanner_trust,
        args.require_scanner,
    )

    payload = {
        "schemaVersion": "1.0.0",
        "auditor": "skill-security-auditor",
        "auditorVersion": VERSION,
        "strict": args.strict,
        "mode": args.mode,
        "securityVerdict": verdict,
        "enrolmentReady": verdict == "Eligible for enrolment",
        "scannerRequired": args.require_scanner,
        "analysisLines": analysis_lines(scanner),
        "skillspector": scanner,
        "scannerTrust": scanner_trust,
        "results": results,
        "safetyRecord": {
            "targetFilesModified": False,
            "targetScriptsExecuted": False,
            "targetUrlsFetched": False,
            "dependenciesInstalled": False,
            "trustRegistryModified": False,
        },
    }

    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif args.format == "sarif":
        print(json.dumps(
            sarif_output(results, scanner),
            ensure_ascii=False,
            indent=2,
        ))
    else:
        print_markdown(payload)

    return 0 if verdict == "Eligible for enrolment" else 1


if __name__ == "__main__":
    raise SystemExit(main())
