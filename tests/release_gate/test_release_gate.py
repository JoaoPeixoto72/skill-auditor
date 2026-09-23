from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2] / "skills" / "skill-release-gate"
GATE = ROOT / "scripts" / "release-gate.py"


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.skill = self.root / "skill"
        self.skill.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return path

    def readiness(self, verdict: str = "Ready", *, semantic_complete: bool = True) -> Path:
        return self.write("readiness.json", {
            "auditor": "skill-readiness-auditor",
            "semanticReviewComplete": semantic_complete,
            "results": [{
                "skill_directory": str(self.skill),
                "readiness_verdict": verdict,
                "security_status": "Separate report available",
                "semantic_review_complete": semantic_complete,
                "semantic_checks_required": [],
            }],
        })

    def security(
        self,
        verdict: str = "Eligible for enrolment",
        *,
        strict: bool = True,
        complete: str = "COMPLETE",
        gate_required: bool = False,
        enforcement: str = "NOT_REQUIRED",
        scanner_required: bool = False,
    ) -> Path:
        return self.write("security.json", {
            "auditor": "skill-security-auditor",
            "strict": strict,
            "scannerRequired": scanner_required,
            "securityVerdict": verdict,
            "enrolmentReady": verdict == "Eligible for enrolment",
            "skillspector": {
                "completeness": complete,
            },
            "results": [{
                "skill": str(self.skill),
                "requiresRuntimeGate": gate_required,
                "runtimeEnforcement": enforcement,
            }],
        })

    def run_gate(
        self,
        readiness: Path,
        security: Path,
        action: str = "install",
        *extra: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        process = subprocess.run(
            [
                sys.executable,
                str(GATE),
                "--readiness-report",
                str(readiness),
                "--security-report",
                str(security),
                "--action",
                action,
                "--format",
                "json",
                *extra,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        return process, json.loads(process.stdout)

    def test_eligible_reports_allow_install(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(),
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["finalDecision"], "Eligible")

    def test_security_reject_has_precedence(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security("Reject"),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Reject")

    def test_readiness_reject_has_precedence(self) -> None:
        process, result = self.run_gate(
            self.readiness("Reject"),
            self.security(),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Reject")

    def test_readiness_revision_blocks_release(self) -> None:
        process, result = self.run_gate(
            self.readiness("Needs revision"),
            self.security(),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            result["finalDecision"],
            "Needs revision",
        )

    def test_incomplete_security_analysis_holds(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(complete="PARTIAL"),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")

    def test_absent_scanner_is_not_missing_evidence(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(complete="UNAVAILABLE"),
        )
        self.assertEqual(result["finalDecision"], "Eligible")
        self.assertEqual(process.returncode, 0)

    def test_required_scanner_must_have_run(self) -> None:
        _, result = self.run_gate(
            self.readiness(),
            self.security(complete="UNAVAILABLE", scanner_required=True),
        )
        self.assertEqual(result["finalDecision"], "Hold")

    def test_runtime_gate_must_be_verified(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(
                gate_required=True,
                enforcement="UNVERIFIED",
            ),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")
        self.assertIn(
            "verified Runtime Gate enforcement",
            result["missingEvidence"],
        )

    def test_enrol_requires_action_evidence(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(),
            "enrol",
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")
        self.assertIn(
            "bundleIntegrity",
            result["missingEvidence"],
        )
        self.assertIn(
            "operatorAuthorization",
            result["missingEvidence"],
        )

    def test_enrol_with_action_evidence_is_eligible(self) -> None:
        evidence = self.write("evidence.json", {
            "bundleIntegrity": "sha256:test",
            "operatorAuthorization": "change-123",
        })

        process, result = self.run_gate(
            self.readiness(),
            self.security(),
            "enrol",
            "--action-evidence",
            str(evidence),
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["finalDecision"], "Eligible")

    def test_accepted_risks_require_operator_record(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security("Eligible with accepted risks"),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")

    def test_complete_risk_acceptance_is_preserved(self) -> None:
        acceptance = self.write("acceptance.json", {
            "findingId": "SEC-123",
            "scope": "one optional endpoint",
            "justification": "Business requirement",
            "compensatingControls": ["egress allowlist"],
            "approvedBy": "security-operator",
            "approvedAt": "2030-01-01T00:00:00Z",
            "expiresAt": "2030-06-01T00:00:00Z",
        })

        process, result = self.run_gate(
            self.readiness(),
            self.security("Eligible with accepted risks"),
            "install",
            "--risk-acceptance",
            str(acceptance),
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            result["finalDecision"],
            "Eligible with accepted risks",
        )

    def test_target_mismatch_holds(self) -> None:
        security = self.write("security-other.json", {
            "auditor": "skill-security-auditor",
            "securityVerdict": "Eligible for enrolment",
            "enrolmentReady": True,
            "skillspector": {
                "completeness": "COMPLETE",
            },
            "results": [{
                "skill": str(self.root / "other-skill"),
                "requiresRuntimeGate": False,
                "runtimeEnforcement": "NOT_REQUIRED",
            }],
        })

        process, result = self.run_gate(
            self.readiness(),
            security,
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")

    def test_non_strict_security_causes_hold(self) -> None:
        process, result = self.run_gate(
            self.readiness(),
            self.security(strict=False),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")
        self.assertIn(
            "strict security audit (--strict required)",
            result["missingEvidence"],
        )

    def test_incomplete_semantic_readiness_causes_hold(self) -> None:
        process, result = self.run_gate(
            self.readiness(semantic_complete=False),
            self.security(),
        )
        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["finalDecision"], "Hold")
        self.assertIn(
            "completed semantic readiness review",
            result["missingEvidence"],
        )


if __name__ == "__main__":
    unittest.main()
