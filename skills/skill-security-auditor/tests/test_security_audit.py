from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDITOR = ROOT / "scripts" / "security-audit.py"

# Attack payloads live in tests/fixtures/, which the auditor excludes.
# Inlining them here would make every self-audit of this skill report its own
# test suite as malicious, and the alternative — obfuscating them to dodge the
# scanner — would be worse.
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class SecurityAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.skill = self.root / "safe-skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text(
            "---\n"
            "name: safe-skill\n"
            'description: "Process local files. Do not use for network tasks."\n'
            "allowed-tools: [Read]\n"
            "---\n"
            "# safe-skill\n",
            encoding="utf-8",
        )
        (self.skill / "external-resources.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "hasExternalResources": False,
                "requiresRuntimeGate": False,
                "resources": [],
            }),
            encoding="utf-8",
        )
        self.scanner = self.root / "scanner.json"
        self.scanner.write_text(
            json.dumps({
                "status": "COMPLETE",
                "completeness": "COMPLETE",
                "scannerVersion": "test",
                "findings": [],
            }),
            encoding="utf-8",
        )
        self.trust = self.root / "trust.json"
        self.trust.write_text(
            json.dumps({"trust": "VERIFIED", "errors": []}),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_audit(
        self,
        strict: bool = True,
        trust: bool = False,
        extra: tuple[str, ...] = (),
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        command = [
            sys.executable,
            str(AUDITOR),
            str(self.skill),
            "--format",
            "json",
            "--skillspector-report",
            str(self.scanner),
        ]
        if strict:
            command.append("--strict")
        if trust:
            command.extend(["--scanner-trust", str(self.trust)])
        command.extend(extra)

        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return process, json.loads(process.stdout)

    def findings(self, payload: dict) -> list[dict]:
        return [
            finding
            for result in payload["results"]
            for finding in result["findings"]
        ]

    def documentation_matches(self, payload: dict) -> list[dict]:
        return [
            item
            for result in payload["results"]
            for item in result["documentationMatches"]
        ]

    def test_safe_local_skill_is_eligible(self) -> None:
        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            payload["securityVerdict"],
            "Eligible for enrolment",
        )

    def test_injection_is_rejected(self) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(fixture("injection.snippet"))

        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Reject")

    def test_obfuscated_execution_is_rejected(self) -> None:
        scripts = self.skill / "scripts"
        scripts.mkdir()
        (scripts / "bad.sh").write_text(
            fixture("obfuscated.sh.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Reject")

    def test_undeclared_network_url_is_rejected(self) -> None:
        scripts = self.skill / "scripts"
        scripts.mkdir()
        (scripts / "client.py").write_text(
            fixture("network-client.py.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Reject")

    def test_invalid_tier_one_hash_is_rejected(self) -> None:
        url = fixture("tier1-url.snippet").strip()

        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(f"\n{url}\n")

        (self.skill / "external-resources.json").write_text(
            json.dumps({
                "version": "1.0.0",
                "hasExternalResources": True,
                "requiresRuntimeGate": True,
                "resources": [{
                    "url": url,
                    "tier": 1,
                    "purpose": "Immutable data",
                    "maxBytes": 4096,
                    "hash": "invalid",
                }],
            }),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Reject")

    def test_incomplete_scanner_causes_hold(self) -> None:
        self.scanner.write_text(
            json.dumps({
                "status": "PARTIAL",
                "completeness": "PARTIAL",
                "findings": [],
            }),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Hold")

    def test_non_strict_mode_causes_hold(self) -> None:
        process, payload = self.run_audit(strict=False)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["securityVerdict"], "Hold")
        self.assertFalse(payload["enrolmentReady"])

    # Documentation context

    def test_prohibition_clause_is_not_a_finding(self) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(fixture("prohibition-block.md.snippet"))

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

        reasons = {item["reason"] for item in self.documentation_matches(payload)}
        self.assertTrue(
            any("negated" in reason for reason in reasons),
            reasons,
        )

    def test_negated_declaration_is_not_a_finding(self) -> None:
        (self.skill / "instruments.yaml").write_text(
            fixture("negated-declaration.yaml.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

    def test_suppressed_match_stays_visible(self) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(fixture("non-goals.md.snippet"))

        _, payload = self.run_audit()
        titles = {item["title"] for item in self.documentation_matches(payload)}
        self.assertIn("Trust or Runtime Gate modification detected", titles)

    def test_payload_cannot_exonerate_itself(self) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(fixture("framed-injection.snippet"))

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Reject")
        self.assertEqual(process.returncode, 1)

    def test_prose_markers_do_not_suppress_code(self) -> None:
        scripts = self.skill / "scripts"
        scripts.mkdir()
        (scripts / "bad.sh").write_text(
            fixture("obfuscated-with-prose.sh.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Reject")
        self.assertEqual(process.returncode, 1)

    # External-resource classification

    def test_documentation_url_is_not_a_blocker(self) -> None:
        (self.skill / "README.md").write_text(
            fixture("doc-url.md.snippet"),
            encoding="utf-8",
        )

        _, payload = self.run_audit()
        findings = [
            finding
            for finding in self.findings(payload)
            if "docs.internal-corp.net" in finding["evidence"]
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Minor")
        self.assertEqual(findings[0]["title"], "Undeclared documentation URL")

    def test_placeholder_host_is_not_a_finding(self) -> None:
        (self.skill / "README.md").write_text(
            fixture("placeholder-url.md.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

        reasons = {item["reason"] for item in self.documentation_matches(payload)}
        self.assertIn("reserved or single-label placeholder host", reasons)

    def test_non_executable_fence_is_documentation(self) -> None:
        (self.skill / "README.md").write_text(
            fixture("plain-fence-url.md.snippet"),
            encoding="utf-8",
        )

        _, payload = self.run_audit()
        severities = {
            finding["severity"]
            for finding in self.findings(payload)
            if "package.zip" in finding["evidence"]
        }
        self.assertEqual(severities, {"Minor"})

    def test_executable_fence_is_runtime(self) -> None:
        (self.skill / "README.md").write_text(
            fixture("bash-fence-url.md.snippet"),
            encoding="utf-8",
        )

        _, payload = self.run_audit()
        titles = {
            finding["title"]
            for finding in self.findings(payload)
            if "payload.sh" in finding["evidence"]
        }
        self.assertIn("Undeclared runtime-capable external URL", titles)

    def test_shell_glob_is_not_a_url(self) -> None:
        scripts = self.skill / "scripts"
        scripts.mkdir()
        (scripts / "guard.sh").write_text(
            fixture("glob-guard.sh.snippet"),
            encoding="utf-8",
        )

        _, payload = self.run_audit()
        observed = [
            url
            for result in payload["results"]
            for url in result["observedUrls"]
        ]
        self.assertEqual(observed, [])

    # Target discovery

    def test_test_directory_is_scanned(self) -> None:
        tests = self.skill / "tests"
        tests.mkdir()
        (tests / "payload.sh").write_text(
            fixture("obfuscated.sh.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Reject")
        self.assertEqual(process.returncode, 1)

    def test_fixture_directory_is_excluded(self) -> None:
        fixtures = self.skill / "fixtures"
        fixtures.mkdir()
        (fixtures / "payload.sh").write_text(
            fixture("obfuscated.sh.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

    def test_generated_cache_is_excluded(self) -> None:
        cache = self.skill / ".pytest_cache"
        cache.mkdir()
        (cache / "README.md").write_text(
            fixture("cache-readme.md.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

    # Scanner supply chain

    def test_failed_scanner_trust_causes_hold(self) -> None:
        self.trust.write_text(
            json.dumps({
                "trust": "FAILED",
                "errors": ["Binary hash mismatch"],
            }),
            encoding="utf-8",
        )

        process, payload = self.run_audit(trust=True)
        self.assertEqual(payload["securityVerdict"], "Hold")
        self.assertEqual(process.returncode, 1)

    def test_verified_scanner_trust_allows_eligibility(self) -> None:
        process, payload = self.run_audit(trust=True)
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

    def test_failed_trust_never_masks_a_blocker(self) -> None:
        self.trust.write_text(json.dumps({"trust": "FAILED", "errors": []}), encoding="utf-8")
        self.append(fixture("injection.snippet"))
        _, payload = self.run_audit(trust=True)
        self.assertEqual(payload["securityVerdict"], "Reject")

    def test_scanner_do_not_install_rejects(self) -> None:
        self.scanner.write_text(json.dumps({
            "completeness": "COMPLETE", "recommendation": "DO_NOT_INSTALL", "findings": [],
        }), encoding="utf-8")
        _, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Reject")

    # SkillSpector is optional

    def unavailable_scanner(self) -> None:
        self.scanner.write_text(json.dumps({
            "status": "UNAVAILABLE", "completeness": "UNAVAILABLE", "findings": [],
        }), encoding="utf-8")

    def test_missing_scanner_still_decides(self) -> None:
        self.unavailable_scanner()
        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(payload["analysisLines"], ["project-policy"])
        self.assertEqual(process.returncode, 0)

    def test_require_scanner_holds_without_it(self) -> None:
        self.unavailable_scanner()
        _, payload = self.run_audit(extra=("--require-scanner",))
        self.assertEqual(payload["securityVerdict"], "Hold")

    # Beyond English keywords: the gap SkillSpector names in its own README

    def append(self, text: str) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(text)

    def titles(self, payload: dict) -> set[str]:
        return {finding["title"] for finding in self.findings(payload)}

    def test_portuguese_override_is_rejected_without_scanner(self) -> None:
        self.unavailable_scanner()
        self.append(fixture("override-pt.snippet"))
        _, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Reject")
        self.assertIn("Instruction-override directive detected", self.titles(payload))

    def test_concealment_is_not_exonerated_by_its_negation(self) -> None:
        for name in ("concealment-en.snippet", "concealment-pt.snippet"):
            with self.subTest(name):
                self.setUp()
                self.append(fixture(name))
                _, payload = self.run_audit()
                self.assertIn("Instruction to conceal behaviour from the user", self.titles(payload))
                self.assertEqual(payload["securityVerdict"], "Reject")

    def test_audit_deception_is_rejected(self) -> None:
        self.append(fixture("audit-deception-pt.snippet"))
        _, payload = self.run_audit()
        self.assertIn("Instruction to deceive an auditor", self.titles(payload))

    def test_ux_defect_prose_is_not_concealment(self) -> None:
        self.append(fixture("ux-defect.md.snippet"))
        _, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")

    def test_unicode_tag_characters_are_detected(self) -> None:
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "hidden")
        self.append(f"Notes.{hidden}\n")
        _, payload = self.run_audit()
        self.assertIn("Invisible or bidirectional Unicode detected", self.titles(payload))

    def test_description_claiming_every_request_holds(self) -> None:
        text = (self.skill / "SKILL.md").read_text(encoding="utf-8")
        (self.skill / "SKILL.md").write_text(
            text.replace("Process local files.", "Process local files for every request."),
            encoding="utf-8",
        )
        _, payload = self.run_audit()
        self.assertIn("Description claims every request", self.titles(payload))
        self.assertEqual(payload["securityVerdict"], "Hold")

    # Persistence

    def test_bare_persistence_topic_is_not_a_finding(self) -> None:
        (self.skill / "README.md").write_text(
            fixture("persistence-prose.md.snippet"),
            encoding="utf-8",
        )

        process, payload = self.run_audit()
        self.assertEqual(payload["securityVerdict"], "Eligible for enrolment")
        self.assertEqual(process.returncode, 0)

    def test_persistence_operation_is_a_finding(self) -> None:
        scripts = self.skill / "scripts"
        scripts.mkdir()
        (scripts / "install.sh").write_text(
            fixture("persistence.sh.snippet"),
            encoding="utf-8",
        )

        _, payload = self.run_audit()
        titles = {finding["title"] for finding in self.findings(payload)}
        self.assertIn("Persistence-related behavior detected", titles)


if __name__ == "__main__":
    unittest.main()
