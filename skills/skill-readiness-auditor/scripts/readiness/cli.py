"""Command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from .audit import audit_target, result_to_dict
from .files import discover_targets
from .model import VALID_PROFILES, VERSION
from .report import print_markdown


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run deterministic mechanical readiness checks "
            "against one Agent Skill or a skills repository."
        )
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="SKILL.md, skill directory, or repository root",
    )

    parser.add_argument(
        "--target",
        choices=("skill", "repo"),
        default=None,
        help="Force single-skill or repository discovery mode",
    )

    parser.add_argument(
        "--depth",
        choices=("quick", "standard", "deep"),
        default="standard",
        help="Requested semantic review depth",
    )

    parser.add_argument(
        "--model",
        choices=tuple(sorted(VALID_PROFILES)),
        default=None,
        help="Override the readiness model profile",
    )

    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Alias for --format json",
    )

    parser.add_argument(
        "--semantic-complete",
        action="store_true",
        help="Attest that semantic instruction and trigger reviews have been completed",
    )

    return parser.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    arguments = parse_arguments()
    output_format = (
        "json"
        if arguments.json
        else arguments.format
    )

    requested_path = Path(arguments.path)

    try:
        targets, target_root = discover_targets(
            requested_path,
            arguments.target,
        )
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    results = [
        audit_target(
            skill_md=target,
            requested_root=target_root,
            depth=arguments.depth,
            requested_profile=arguments.model,
            semantic_complete=arguments.semantic_complete,
        )
        for target in targets
    ]

    if output_format == "json":
        payload = {
            "schemaVersion": "1.0.0",
            "auditor": "skill-readiness-auditor",
            "auditorVersion": VERSION,
            "targetRoot": str(target_root),
            "targetCount": len(results),
            "semanticBatchLimit": 5,
            "semanticReviewComplete": (
                all(r.semantic_review_complete for r in results)
                if results
                else False
            ),
            "results": [
                result_to_dict(result)
                for result in results
            ],
            "securityCertification": (
                "Not performed by skill-readiness-auditor."
            ),
        }

        print(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_markdown(results, target_root)

    has_blocking_findings = any(
        item.severity in {"Blocker", "Major"}
        for result in results
        for item in result.findings
    )

    return 1 if has_blocking_findings else 0
