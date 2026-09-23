"""Command line."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from .model import VERSION
from .report import print_markdown, sarif_output
from .scan import scan_skill
from .text import discover
from .verdict import analysis_lines, decide_verdict, load_scanner_trust, load_skillspector


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
