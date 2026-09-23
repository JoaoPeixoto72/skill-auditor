#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Decisions are reported with `·` and `§`. Redirected stdout defaults to the
# system locale on Windows, which writes cp1252 bytes downstream tools cannot
# decode as UTF-8.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


VERSION = "1.0.0"

READINESS_ACCEPTABLE = {
    "Ready",
    "Ready with suggestions",
    "Approve with nits",
}

SECURITY_ACCEPTABLE = {
    "Eligible for enrolment",
    "Eligible with accepted risks",
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ValueError(f"Cannot read {path}: {error}") from error

    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")

    return value


def extract_readiness(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("auditor") != "skill-readiness-auditor":
        raise ValueError("Invalid readiness-report producer")

    results = report.get("results")

    if not isinstance(results, list) or len(results) != 1:
        raise ValueError(
            "Release gate requires exactly one readiness target"
        )

    result = results[0]

    return {
        "target": result.get("skill_directory") or result.get("skill"),
        "verdict": result.get("readiness_verdict"),
        "securityStatus": result.get("security_status"),
        "semanticReviewComplete": result.get(
            "semantic_review_complete",
            report.get("semanticReviewComplete", False),
        ),
        "semanticChecksRequired": result.get(
            "semantic_checks_required",
            [],
        ),
        "bundleHash": result.get("bundleHash") or result.get("bundle_hash") or report.get("bundleHash"),
    }


def extract_security(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("auditor") != "skill-security-auditor":
        raise ValueError("Invalid security-report producer")

    results = report.get("results")

    if not isinstance(results, list) or len(results) != 1:
        raise ValueError(
            "Release gate requires exactly one security target"
        )

    result = results[0]
    scanner = report.get("skillspector", {})

    return {
        "target": result.get("skill"),
        "verdict": report.get("securityVerdict"),
        "strict": report.get("strict", False),
        "completeness": scanner.get("completeness"),
        "scannerRequired": report.get("scannerRequired", False),
        "requiresRuntimeGate": result.get(
            "requiresRuntimeGate",
            False,
        ),
        "runtimeEnforcement": result.get(
            "runtimeEnforcement",
            "UNVERIFIED",
        ),
        "enrolmentReady": report.get(
            "enrolmentReady",
            False,
        ),
        "bundleHash": result.get("bundleHash") or result.get("bundle_hash") or report.get("bundleHash"),
    }


def canonical_target(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return str(Path(value).resolve())


def load_optional(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return load_json(Path(path).resolve())


def decide(
    readiness: dict[str, Any],
    security: dict[str, Any],
    action: str,
    risk_acceptance: dict[str, Any] | None,
    action_evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    missing: list[str] = []
    next_actions: list[str] = []

    readiness_target = canonical_target(readiness["target"])
    security_target = canonical_target(security["target"])

    if not readiness_target or not security_target:
        missing.append("canonical target identity")
    elif readiness_target != security_target:
        reasons.append(
            "Readiness and security reports identify different targets."
        )

    readiness_bundle = readiness.get("bundleHash")
    security_bundle = security.get("bundleHash")
    if readiness_bundle and security_bundle and readiness_bundle != security_bundle:
        reasons.append(
            "Readiness and security reports identify different bundle hashes."
        )

    readiness_verdict = readiness["verdict"]
    security_verdict = security["verdict"]

    if security_verdict == "Reject":
        decision = "Reject"
        reasons.append("Security audit rejected the skill.")
    elif readiness_verdict == "Reject":
        decision = "Reject"
        reasons.append("Readiness audit rejected the skill.")
    elif security_verdict == "Hold":
        decision = "Hold"
        reasons.append("Security audit requires additional evidence.")
    elif readiness_verdict == "Needs revision":
        decision = "Needs revision"
        reasons.append("Readiness defects require correction.")
    elif security_verdict not in SECURITY_ACCEPTABLE:
        decision = "Hold"
        reasons.append("Unknown or unacceptable security verdict.")
    elif readiness_verdict not in READINESS_ACCEPTABLE:
        decision = "Hold"
        reasons.append("Unknown or unacceptable readiness verdict.")
    else:
        decision = "Eligible"

    if reasons and any(
        "different targets" in reason
        for reason in reasons
    ):
        decision = "Hold"

    # SkillSpector is optional: absent and not required, the security report
    # decided on its project-policy line alone. Present or required, its
    # evidence must be complete.
    scanner_absent = security["completeness"] == "UNAVAILABLE"
    if security["completeness"] != "COMPLETE" and (
        security["scannerRequired"] or not scanner_absent
    ):
        if decision != "Reject":
            decision = "Hold"
        missing.append("complete SkillSpector evidence")

    if (
        security["requiresRuntimeGate"]
        and security["runtimeEnforcement"] != "VERIFIED"
    ):
        if decision != "Reject":
            decision = "Hold"
        missing.append("verified Runtime Gate enforcement")

    if not security.get("strict"):
        missing.append("strict security audit (--strict required)")

    if not readiness.get("semanticReviewComplete"):
        missing.append("completed semantic readiness review")

    if security_verdict == "Eligible with accepted risks":
        required_acceptance = {
            "findingId",
            "scope",
            "justification",
            "compensatingControls",
            "approvedBy",
            "approvedAt",
            "expiresAt",
        }

        if (
            not isinstance(risk_acceptance, dict)
            or not required_acceptance.issubset(risk_acceptance)
        ):
            decision = "Hold"
            missing.append("complete operator risk acceptance")
        elif decision == "Eligible":
            decision = "Eligible with accepted risks"

    evidence = action_evidence or {}

    action_requirements = {
        "install": [],
        "publish": [
            "version",
            "provenance",
        ],
        "sign": [
            "finalBundleIdentity",
            "signerAuthorization",
        ],
        "enrol": [
            "bundleIntegrity",
            "operatorAuthorization",
        ],
        "reaudit": [
            "quarantineReason",
            "remediationEvidence",
            "operatorAuthorization",
        ],
    }

    for field in action_requirements[action]:
        if not evidence.get(field):
            missing.append(field)

    if missing and decision not in {"Reject", "Needs revision"}:
        decision = "Hold"

    if decision == "Reject":
        next_actions.append(
            "Resolve the rejecting findings before repeating either audit."
        )
    elif decision == "Needs revision":
        next_actions.append(
            "Correct readiness defects and generate a new readiness report."
        )
    elif decision == "Hold":
        next_actions.append(
            "Provide the missing evidence and rerun the release gate."
        )
    else:
        next_actions.append(
            f"Proceed with the privileged {action} process."
        )

    return {
        "schemaVersion": "1.0.0",
        "gate": "skill-release-gate",
        "gateVersion": VERSION,
        "action": action,
        "target": readiness_target or security_target,
        "readinessVerdict": readiness_verdict,
        "securityVerdict": security_verdict,
        "finalDecision": decision,
        "reasons": sorted(set(reasons)),
        "missingEvidence": sorted(set(missing)),
        "nextActions": next_actions,
        "mutations": {
            "targetModified": False,
            "reportsModified": False,
            "trustRegistryModified": False,
            "skillInstalled": False,
            "skillSigned": False,
        },
    }


def print_markdown(result: dict[str, Any]) -> None:
    print(f"# Skill Release Gate: {result['target']}")
    print()
    print(f"**Action:** {result['action']}  ")
    print(f"**Final decision:** {result['finalDecision']}  ")
    print(
        f"**Readiness verdict:** "
        f"{result['readinessVerdict']}  "
    )
    print(
        f"**Security verdict:** "
        f"{result['securityVerdict']}"
    )
    print()

    print("## Reasons")
    print()
    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"- {reason}")
    else:
        print("- Independent reports satisfy the base decision matrix.")

    print()
    print("## Missing evidence")
    print()
    if result["missingEvidence"]:
        for item in result["missingEvidence"]:
            print(f"- {item}")
    else:
        print("- None.")

    print()
    print("## Next actions")
    print()
    for item in result["nextActions"]:
        print(f"- {item}")

    print()
    print("## Mutations")
    print()
    print("- Target modified: no")
    print("- Reports modified: no")
    print("- Trust Registry modified: no")
    print("- Skill installed: no")
    print("- Skill signed: no")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness-report", required=True)
    parser.add_argument("--security-report", required=True)
    parser.add_argument(
        "--action",
        required=True,
        choices=("install", "publish", "sign", "enrol", "reaudit"),
    )
    parser.add_argument("--risk-acceptance")
    parser.add_argument("--action-evidence")
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
    )
    args = parser.parse_args()

    try:
        readiness_report = load_json(
            Path(args.readiness_report).resolve()
        )
        security_report = load_json(
            Path(args.security_report).resolve()
        )
        readiness = extract_readiness(readiness_report)
        security = extract_security(security_report)
        risk_acceptance = load_optional(args.risk_acceptance)
        action_evidence = load_optional(args.action_evidence)
    except ValueError as error:
        result = {
            "schemaVersion": "1.0.0",
            "gate": "skill-release-gate",
            "gateVersion": VERSION,
            "action": args.action,
            "target": "",
            "readinessVerdict": "Unknown",
            "securityVerdict": "Unknown",
            "finalDecision": "Hold",
            "reasons": [str(error)],
            "missingEvidence": ["valid independent reports"],
            "nextActions": [
                "Regenerate valid readiness and security reports."
            ],
            "mutations": {
                "targetModified": False,
                "reportsModified": False,
                "trustRegistryModified": False,
                "skillInstalled": False,
                "skillSigned": False,
            },
        }
    else:
        result = decide(
            readiness,
            security,
            args.action,
            risk_acceptance,
            action_evidence,
        )

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_markdown(result)

    return 0 if result["finalDecision"] in {
        "Eligible",
        "Eligible with accepted risks",
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
