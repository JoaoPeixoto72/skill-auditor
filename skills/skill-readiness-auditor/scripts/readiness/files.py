"""Reading a skill: files, frontmatter, discovery, resources and documented commands."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Iterable, Sequence
import yaml
from .model import EXCLUDED_DIRECTORIES, PLUGIN_MANIFESTS, TEXT_EXTENSIONS, clean_excerpt
from .patterns import BASH_COMMAND_RE


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
        loader = UniqueKeyLoader(raw)  # a SafeLoader: builds only plain data
        try:
            parsed = loader.get_single_data()
        finally:
            loader.dispose()
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


def is_project_skill(skill_dir: Path) -> bool:
    parts = skill_dir.parts
    return any(
        parts[i] in (".claude", ".agents") and parts[i + 1] == "skills"
        for i in range(len(parts) - 1)
    )


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
