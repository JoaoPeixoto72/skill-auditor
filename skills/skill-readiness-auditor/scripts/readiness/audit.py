"""One target audited end to end, and its result as data."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from .checks_content import check_absolute_paths, check_audit_manipulation, check_body_size, check_model_fit, check_reference_files, check_resources, check_scripts, scan_security_handoffs
from .checks_frontmatter import check_description_routing, check_frontmatter, check_hooks_and_subagents, check_permission_commands, check_platform_rules, check_read_only_permissions
from .description import resolve_profile
from .files import determine_repository_root, extract_frontmatter, read_text
from .model import Finding, SEVERITY_WEIGHT, SecurityHandoff, TargetResult, add_finding, release_status_for, verdict_for


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
