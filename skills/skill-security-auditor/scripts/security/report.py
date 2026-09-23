"""SARIF and Markdown output."""

from __future__ import annotations

import json
from typing import Any, Iterable
from .model import VERSION


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
