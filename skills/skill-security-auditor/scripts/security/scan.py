"""The project-policy line over one skill directory."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from .detectors import (  # noqa: E402
    AUDIT_DECEPTION_RE,
    CONCEALMENT_RE,
    OVERRIDE_RE,
    TRIGGER_HIJACK_RE,
    description_of,
    first_invisible,
)
from .manifest import load_manifest, url_usage
from .model import CODE_EXTENSIONS, DEPENDENCY_FILES, Finding, add_finding, clean
from .patterns import INJECTION_RE, MARKDOWN_IMAGE_RE, MUTABLE_DEPENDENCY_RE, NETWORK_RE, OBFUSCATION_RE, PERSISTENCE_RE, REGISTRY_TAMPER_RE, SENSITIVE_RE, URL_RE, placeholder_host
from .text import canonical_url, documentation_context, fenced_code_spans, iter_files, line_index_at, line_location, observes_network_call, pattern_definition_spans, read_text


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
