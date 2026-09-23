"""SkillSpector evidence, scanner trust, and the security verdict."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def load_skillspector(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {
            "status": "UNAVAILABLE",
            "completeness": "UNAVAILABLE",
            "findings": [],
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {
            "status": "FAILED",
            "completeness": "FAILED",
            "findings": [],
        }
    except Exception as error:
        return {
            "status": "FAILED",
            "completeness": "FAILED",
            "error": str(error),
            "findings": [],
        }


def load_scanner_trust(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"trust": "UNVERIFIED", "errors": ["No scanner-trust record supplied."]}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        return {"trust": "FAILED", "errors": [f"Unreadable scanner-trust record: {error}"]}

    if not isinstance(data, dict) or "trust" not in data:
        return {"trust": "FAILED", "errors": ["Malformed scanner-trust record."]}

    return data


def scanner_material_severity(finding: dict[str, Any]) -> str:
    value = str(
        finding.get("severity")
        or finding.get("level")
        or finding.get("properties", {}).get("severity", "")
    ).upper()
    return value


def analysis_lines(scanner: dict[str, Any]) -> list[str]:
    """Which independent evidence lines actually ran."""
    lines = ["project-policy"]
    if scanner.get("completeness") not in (None, "UNAVAILABLE", "FAILED"):
        lines.append("skillspector")
    return lines


def decide_verdict(
    project_results: list[dict[str, Any]],
    scanner: dict[str, Any],
    strict: bool,
    scanner_trust: dict[str, Any] | None = None,
    require_scanner: bool = False,
) -> str:
    project_findings = [
        finding
        for result in project_results
        for finding in result["findings"]
    ]
    external_severities = {
        scanner_material_severity(item)
        for item in scanner.get("findings", [])
        if isinstance(item, dict)
    }

    # Evidence of harm rejects whatever the state of the other line: a scanner
    # that cannot be trusted never makes a malicious finding less true.
    if any(finding["severity"] == "Blocker" for finding in project_findings):
        return "Reject"

    # A CRITICAL finding is concrete code. SkillSpector's DO_NOT_INSTALL is a
    # score over all findings, and it cannot tell a skill that documents an
    # attack from one that performs it: a human decides (Hold, below).
    if "CRITICAL" in external_severities:
        return "Reject"

    if scanner_trust and scanner_trust.get("trust") == "FAILED":
        return "Hold"

    if scanner.get("recommendation") == "DO_NOT_INSTALL":
        return "Hold"

    # SkillSpector is optional. Absent, the project-policy line decides alone
    # and the report says so; present, its evidence must be complete.
    completeness = scanner.get("completeness", "UNAVAILABLE")

    if completeness != "UNAVAILABLE" and completeness != "COMPLETE":
        return "Hold"

    if require_scanner and completeness != "COMPLETE":
        return "Hold"

    if any(finding["severity"] == "Major" for finding in project_findings):
        return "Hold"

    if external_severities & {"HIGH", "MEDIUM", "LOW"}:
        return "Hold"

    if not strict:
        return "Hold"

    return "Eligible for enrolment"
