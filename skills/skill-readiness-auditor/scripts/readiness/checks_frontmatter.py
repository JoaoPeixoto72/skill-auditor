"""Checks on the frontmatter, the description and the permission contract."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from .description import begins_with_action, claims_read_only, description_has_negative_boundary, description_has_when_to_use, extract_mandatory_alternatives, sibling_skill_exists
from .files import command_is_permitted, extract_commands, location_for, normalize_tool_collection
from .model import Finding, SecurityHandoff, VALID_EFFORTS, VALID_MODELS, add_finding, add_handoff
from .patterns import DESCRIPTION_MAX, NAME_MAX, PERSON_RE, RESERVED_NAME_RE, TIME_SENSITIVE_RE, XML_TAG_RE


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
