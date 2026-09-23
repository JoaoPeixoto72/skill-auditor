"""Reading a bundle: files, fences, clauses, and when a match is documentation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from .model import CODE_EXTENSIONS, EXCLUDED, PROSE_EXTENSIONS, TEXT_EXTENSIONS, clean
from .patterns import ALLOWED_TOOLS_RE, EXECUTABLE_FENCE_LANGUAGES, EXEMPLIFICATION_RE, HEADING_RE, LIST_ITEM_RE, NEGATED_DECLARATION_RE, NEGATION_RE, NETWORK_RE


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
