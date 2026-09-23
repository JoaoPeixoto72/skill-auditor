"""The Markdown report."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Sequence
from .audit import finding_sort_key
from .model import TargetResult, VERSION


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
