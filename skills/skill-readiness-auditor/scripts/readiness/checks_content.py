"""Checks on the body: size, paths, resources, scripts, model fit, security handoffs."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from .files import is_excluded, is_project_skill, iter_text_files, location_for, normalize_resource_reference, plugin_root, read_text, resolve_resource, resource_matches
from .model import DIRECT_EXECUTION_EXTENSIONS, Finding, SCRIPT_EXTENSIONS, SecurityHandoff, add_finding, add_handoff
from .patterns import ABSOLUTE_PATH_RE, AUDIT_MANIPULATION_RE, CREDENTIAL_ACCESS_RE, DEPENDENCY_INSTALL_RE, DISALLOWED_TOOLS_RE, DYNAMIC_IMPORT_RE, ENCODED_CONTENT_RE, ENVIRONMENT_ACCESS_RE, MARKDOWN_LINK_RE, MCP_RE, NETWORK_TOOL_RE, PLUGIN_RESOURCE_RE, PROFILE_PHRASES, RESOURCE_REFERENCE_RE, SHELL_EXECUTION_RE, TOC_RE, URL_RE


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
        entry_point = suffix != ".py" or bool(re.search(r"^if\s+__name__\s*==", text, re.M))
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
