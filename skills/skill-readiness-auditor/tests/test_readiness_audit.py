#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
AUDITOR = SKILL_ROOT / "scripts" / "readiness-audit.py"

# Payloads live in tests/fixtures/, which skill-security-auditor excludes.
# Inlining them here would make a security audit of this skill report its own
# test suite as malicious.
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def valid_skill(
    name: str,
    *,
    description: str | None = None,
    allowed_tools: str = "[]",
    extra_frontmatter: str = "",
    body: str = "",
) -> str:
    description = description or (
        "Audit Agent Skills for readiness before release. "
        "Do not use for application code."
    )

    return (
        "---\n"
        f"name: {name}\n"
        f'description: "{description}"\n'
        "argument-hint: \"<target>\"\n"
        "version: 1.0.0\n"
        "model: inherit\n"
        "effort: medium\n"
        f"allowed-tools: {allowed_tools}\n"
        f"{extra_frontmatter}"
        "---\n"
        f"# {name}\n\n"
        "Inspect the target and return a readiness report.\n"
        f"{body}"
    )


class ReadinessAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def create_skill(
        self,
        name: str,
        content: str | None = None,
        *,
        parent: Path | None = None,
    ) -> Path:
        parent = parent or self.root
        skill_directory = parent / name
        skill_directory.mkdir(parents=True, exist_ok=True)

        skill_md = skill_directory / "SKILL.md"
        skill_md.write_text(
            content or valid_skill(name),
            encoding="utf-8",
        )

        return skill_directory

    def run_audit(
        self,
        target: Path,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(AUDITOR),
                str(target),
                "--format",
                "json",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def parse_result(
        self,
        process: subprocess.CompletedProcess[str],
        index: int = 0,
    ) -> dict:
        self.assertTrue(
            process.stdout.strip(),
            msg=f"Expected JSON output. stderr={process.stderr}",
        )

        payload = json.loads(process.stdout)
        return payload["results"][index]

    def finding_titles(self, result: dict) -> list[str]:
        return [
            finding["title"]
            for finding in result["findings"]
        ]

    def test_plugin_prefixed_resource_resolves_from_plugin_root(self) -> None:
        plugin = self.root / "plugin"
        (plugin / "scripts").mkdir(parents=True)
        (plugin / "plugin.json").write_text("{}", encoding="utf-8")
        (plugin / "scripts" / "shared.py").write_text("", encoding="utf-8")
        skill = self.create_skill(
            "shared-skill",
            valid_skill(
                "shared-skill",
                body=(
                    "Run `python <plugin>/scripts/shared.py`.\n"
                    "Then `python <plugin>/scripts/absent.py`.\n"
                ),
            ),
            parent=plugin / "skills",
        )

        result = self.parse_result(self.run_audit(skill))
        missing = [
            finding["evidence"]
            for finding in result["findings"]
            if finding["title"] == "Referenced local resource is missing"
        ]

        self.assertEqual(missing, ["scripts/absent.py"])

    def test_markdown_link_text_resolves_resource(self) -> None:
        skill = self.create_skill(
            "linked-skill",
            valid_skill(
                "linked-skill",
                body=(
                    "- [references/guide.md](references/guide.md): guide.\n"
                    "- Profiles: `profiles/<name>/{profile.md, assets/}`.\n"
                ),
            ),
        )
        (skill / "references").mkdir()
        (skill / "references" / "guide.md").write_text("guide", encoding="utf-8")
        (skill / "assets").mkdir()

        result = self.parse_result(self.run_audit(skill))

        self.assertNotIn(
            "Referenced local resource is missing",
            self.finding_titles(result),
        )

    def finding_severities(self, result: dict) -> list[str]:
        return [
            finding["severity"]
            for finding in result["findings"]
        ]

    def handoff_categories(self, result: dict) -> list[str]:
        return [
            handoff["category"]
            for handoff in result["security_handoffs"]
        ]

    def test_valid_minimal_skill_has_no_blocking_findings(self) -> None:
        skill = self.create_skill("valid-skill")

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["readiness_verdict"], "Ready")
        self.assertTrue(result["frontmatter_valid"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["security_status"], "Not performed")
        self.assertFalse(result["security_handoff_required"])

    def test_invalid_yaml_is_a_blocker(self) -> None:
        skill = self.create_skill(
            "invalid-yaml",
            (
                "---\n"
                "name: invalid-yaml\n"
                "description: Unquoted value: breaks YAML\n"
                "allowed-tools: []\n"
                "---\n"
                "# invalid-yaml\n"
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["readiness_verdict"], "Reject")
        self.assertIn(
            "Invalid YAML frontmatter",
            self.finding_titles(result),
        )
        self.assertIn(
            "Blocker",
            self.finding_severities(result),
        )

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        skill = self.create_skill(
            "duplicate-key",
            (
                "---\n"
                "name: duplicate-key\n"
                "name: second-name\n"
                'description: "Audit Agent Skills before release. '
                'Do not use for application code."\n'
                "allowed-tools: []\n"
                "---\n"
                "# duplicate-key\n"
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["readiness_verdict"], "Reject")
        self.assertIn(
            "Invalid YAML frontmatter",
            self.finding_titles(result),
        )

        evidence = " ".join(
            finding["evidence"]
            for finding in result["findings"]
        )
        self.assertRegex(evidence, r"duplicate YAML key")

    def test_name_must_match_folder(self) -> None:
        skill = self.create_skill(
            "actual-folder",
            valid_skill("different-name"),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            result["readiness_verdict"],
            "Needs revision",
        )
        self.assertIn(
            "Skill name does not match the containing folder",
            self.finding_titles(result),
        )

    def test_missing_allowed_tools_is_major(self) -> None:
        skill = self.create_skill(
            "missing-tools",
            (
                "---\n"
                "name: missing-tools\n"
                'description: "Audit Agent Skills before release. '
                'Do not use for application code."\n'
                "argument-hint: \"<target>\"\n"
                "version: 1.0.0\n"
                "model: inherit\n"
                "effort: medium\n"
                "---\n"
                "# missing-tools\n\n"
                "Inspect the target.\n"
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertIn(
            "Missing allowed-tools declaration",
            self.finding_titles(result),
        )

    def test_invalid_model_identifier_is_major(self) -> None:
        content = valid_skill(
            "invalid-model",
        ).replace(
            "model: inherit",
            "model: generic",
        )

        skill = self.create_skill(
            "invalid-model",
            content,
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertIn(
            "Unresolvable model identifier",
            self.finding_titles(result),
        )
        self.assertEqual(
            result["model_profile"],
            "generic",
        )

    def test_missing_reference_is_reported(self) -> None:
        skill = self.create_skill(
            "missing-reference",
            valid_skill(
                "missing-reference",
                body=(
                    "\n## Resources\n\n"
                    "Read `references/missing.md` before composing the report.\n"
                ),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            result["readiness_verdict"],
            "Needs revision",
        )
        self.assertIn(
            "Referenced local resource is missing",
            self.finding_titles(result),
        )
        self.assertIn(
            "references/missing.md",
            result["unresolved_resources"],
        )

    def test_missing_script_is_a_blocker(self) -> None:
        skill = self.create_skill(
            "missing-script",
            valid_skill(
                "missing-script",
                allowed_tools="[Read, Bash(bash scripts/check.sh:*)]",
                body=(
                    "\n## Workflow\n\n"
                    "Run `bash scripts/check.sh target`.\n"
                ),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["readiness_verdict"], "Reject")

        matching = [
            finding
            for finding in result["findings"]
            if finding["title"] == "Referenced local resource is missing"
        ]

        self.assertTrue(matching)
        self.assertEqual(matching[0]["severity"], "Blocker")

    def test_existing_local_reference_resolves(self) -> None:
        skill = self.create_skill(
            "local-reference",
            valid_skill(
                "local-reference",
                body=(
                    "\n## Resources\n\n"
                    "Read `references/guide.md` before composing the report.\n"
                ),
            ),
        )

        references = skill / "references"
        references.mkdir()
        (references / "guide.md").write_text(
            "# Guide\n",
            encoding="utf-8",
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertIn(
            "references/guide.md",
            result["resolved_resources"],
        )
        self.assertEqual(
            result["unresolved_resources"],
            [],
        )

    def test_repository_root_resource_is_a_portability_concern(self) -> None:
        repository = self.root / "repository"
        repository.mkdir()

        shared = repository / "schemas"
        shared.mkdir()
        (shared / "report.json").write_text(
            "{}\n",
            encoding="utf-8",
        )

        skills_root = repository / "skills"
        skill = self.create_skill(
            "root-coupled",
            valid_skill(
                "root-coupled",
                body=(
                    "\n## Resources\n\n"
                    "Read `schemas/report.json` before returning.\n"
                ),
            ),
            parent=skills_root,
        )

        process = self.run_audit(
            repository,
            "--target",
            "repo",
        )
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            result["readiness_verdict"],
            "Approve with nits",
        )
        self.assertIn(
            "Resource resolves only from the repository root",
            self.finding_titles(result),
        )
        self.assertEqual(
            result["findings"][0]["confidence"],
            "Inferred",
        )

    def test_permission_pattern_must_match_interpreter_invocation(self) -> None:
        skill = self.create_skill(
            "permission-mismatch",
            valid_skill(
                "permission-mismatch",
                allowed_tools="[Read, Bash(scripts/check.sh:*)]",
                body=(
                    "\n## Workflow\n\n"
                    "Run `bash scripts/check.sh target`.\n"
                ),
            ),
        )

        scripts = skill / "scripts"
        scripts.mkdir()
        script = scripts / "check.sh"
        script.write_text(
            "#!/usr/bin/env bash\nexit 0\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertIn(
            "Documented command is not matched by allowed-tools",
            self.finding_titles(result),
        )

    def test_matching_permission_allows_documented_command(self) -> None:
        skill = self.create_skill(
            "permission-match",
            valid_skill(
                "permission-match",
                allowed_tools="[Read, Bash(bash scripts/check.sh:*)]",
                body=(
                    "\n## Workflow\n\n"
                    "Run `bash scripts/check.sh target`.\n"
                ),
            ),
        )

        scripts = skill / "scripts"
        scripts.mkdir()
        script = scripts / "check.sh"
        script.write_text(
            "#!/usr/bin/env bash\nexit 0\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertNotIn(
            "Documented command is not matched by allowed-tools",
            self.finding_titles(result),
        )

    def test_read_only_skill_must_deny_editing_tools(self) -> None:
        skill = self.create_skill(
            "read-only-skill",
            valid_skill(
                "read-only-skill",
                extra_frontmatter=(
                    "disallowed-tools:\n"
                    "  - Edit\n"
                ),
                body=(
                    "\nThis is a read-only workflow.\n"
                ),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)

        titles = self.finding_titles(result)

        self.assertIn(
            "Read-only skill does not deny multiedit",
            titles,
        )
        self.assertIn(
            "Read-only skill does not deny notebookedit",
            titles,
        )

    def test_external_url_creates_security_handoff_not_security_verdict(self) -> None:
        skill = self.create_skill(
            "external-reference",
            valid_skill(
                "external-reference",
                body=fixture("external-reference.md.snippet"),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["readiness_verdict"], "Ready")
        self.assertTrue(result["security_handoff_required"])
        self.assertEqual(result["security_status"], "Handoff required")
        self.assertIn(
            "external-url",
            self.handoff_categories(result),
        )
        self.assertEqual(
            result["release_status"],
            "Security review required",
        )

    def test_network_tool_creates_security_handoff(self) -> None:
        skill = self.create_skill(
            "network-tool",
            valid_skill(
                "network-tool",
                allowed_tools=fixture("network-allowed-tools.snippet"),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertTrue(result["security_handoff_required"])
        self.assertIn(
            "network-capability",
            self.handoff_categories(result),
        )

    def test_audit_manipulation_in_description_is_a_blocker(self) -> None:
        skill = self.create_skill(
            "audit-manipulation",
            valid_skill(
                "audit-manipulation",
                description=fixture("injection-description.snippet"),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["readiness_verdict"], "Reject")
        self.assertIn(
            "Description attempts to control the readiness audit",
            self.finding_titles(result),
        )
        self.assertIn(
            "audit-manipulation",
            self.handoff_categories(result),
        )

    def test_audit_manipulation_in_html_comment_is_a_blocker(self) -> None:
        skill = self.create_skill(
            "hidden-manipulation",
            valid_skill(
                "hidden-manipulation",
                body=fixture("hidden-manipulation.md.snippet"),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertEqual(result["readiness_verdict"], "Reject")
        self.assertIn(
            "HTML comment attempts to control the readiness audit",
            self.finding_titles(result),
        )

    def test_claude_profile_flags_over_verification(self) -> None:
        skill = self.create_skill(
            "model-fit",
            valid_skill(
                "model-fit",
                body="\n## Workflow\n\nBefore returning, double-check everything.\n",
            ),
        )
        result = self.parse_result(self.run_audit(skill, "--model", "claude"))
        self.assertEqual(result["profile_source"], "--model")
        fits = [f for f in result["findings"] if f["title"] == "Instruction conflicts with the claude profile"]
        self.assertEqual([f["severity"] for f in fits], ["Minor"])

    def test_claude_host_is_detected_from_the_path(self) -> None:
        content = valid_skill("hosted").replace("model: inherit\n", "")
        skill = self.create_skill("hosted", content, parent=self.root / ".claude" / "skills")
        result = self.parse_result(self.run_audit(skill))
        self.assertEqual((result["model_profile"], result["profile_source"]), ("claude", "host: Claude Code"))

    def test_negated_read_only_is_not_a_claim(self) -> None:
        skill = self.create_skill(
            "fixer",
            valid_skill("fixer", allowed_tools="[Read, Edit]",
                        body="\nThis skill is not read-only: it edits what it finds.\n"),
        )
        titles = self.finding_titles(self.parse_result(self.run_audit(skill)))
        self.assertFalse([t for t in titles if "read-only" in t.lower()], titles)

    def test_portuguese_description_is_understood(self) -> None:
        skill = self.create_skill(
            "rever",
            valid_skill("rever", description=(
                "Rever uma mudança depois de mexer no código. Não usar para auditorias da app inteira."
            )),
        )
        titles = self.finding_titles(self.parse_result(self.run_audit(skill)))
        self.assertNotIn("Description has no clear activation condition", titles)
        self.assertNotIn("Description does not begin with a clear action verb", titles)

    def test_sibling_skill_reference_resolves(self) -> None:
        plugin = self.root / "plugin" / "skills"
        tool = plugin / "owner" / "scripts" / "tool.py"
        tool.parent.mkdir(parents=True)
        tool.write_text("print('ok')\n", encoding="utf-8")
        skill = self.create_skill(
            "user",
            valid_skill("user", body="\nRun `../owner/scripts/tool.py` on the diff.\n"),
            parent=plugin,
        )
        result = self.parse_result(self.run_audit(skill))
        self.assertEqual(result["unresolved_resources"], [])
        self.assertIn("../owner/scripts/tool.py", result["discovered_resources"])

    def test_single_and_repository_mode_agree(self) -> None:
        repository = self.root / "project"
        (repository / ".git").mkdir(parents=True)
        (repository / "scripts").mkdir()
        (repository / "scripts" / "check.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        skills = repository / ".claude" / "skills"
        skill = self.create_skill(
            "adapter",
            valid_skill("adapter", body="\nRun `scripts/check.sh` before closing.\n"),
            parent=skills,
        )
        alone = self.finding_titles(self.parse_result(self.run_audit(skill)))
        together = self.finding_titles(self.parse_result(self.run_audit(skills, "--target", "repo")))
        self.assertEqual(sorted(alone), sorted(together))
        self.assertNotIn("Referenced local resource is missing", alone)
        self.assertNotIn("Resource resolves only from the repository root", alone)

    def test_reserved_word_in_name_blocks(self) -> None:
        skill = self.create_skill("claude-helper", valid_skill("claude-helper"))
        titles = self.finding_titles(self.parse_result(self.run_audit(skill)))
        self.assertIn("Skill name uses a reserved word", titles)

    def test_first_person_description_is_flagged(self) -> None:
        skill = self.create_skill("helper", valid_skill("helper", description=(
            "I can audit skills before release. Do not use for application code."
        )))
        titles = self.finding_titles(self.parse_result(self.run_audit(skill)))
        self.assertIn("Description is not written in the third person", titles)

    def test_generic_profile_does_not_apply_profile_specific_phrase_rule(
        self,
    ) -> None:
        skill = self.create_skill(
            "generic-profile",
            valid_skill(
                "generic-profile",
                body=(
                    "\n## Workflow\n\n"
                    "Before returning, double-check everything.\n"
                ),
            ),
        )

        process = self.run_audit(
            skill,
            "--model",
            "generic",
        )
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertNotIn(
            "Instruction conflicts with the generic profile",
            self.finding_titles(result),
        )

    def test_repository_mode_discovers_multiple_skills(self) -> None:
        repository = self.root / "repository"
        skills = repository / "skills"

        self.create_skill(
            "alpha-skill",
            parent=skills,
        )
        self.create_skill(
            "beta-skill",
            parent=skills,
        )

        process = self.run_audit(
            repository,
            "--target",
            "repo",
        )

        self.assertEqual(process.returncode, 0)

        payload = json.loads(process.stdout)

        self.assertEqual(payload["targetCount"], 2)

        discovered = [
            Path(result["skill_directory"]).name
            for result in payload["results"]
        ]

        self.assertEqual(
            discovered,
            ["alpha-skill", "beta-skill"],
        )

    def test_repository_mode_excludes_fixtures(self) -> None:
        repository = self.root / "repository"
        skills = repository / "skills"

        self.create_skill(
            "real-skill",
            parent=skills,
        )

        self.create_skill(
            "hostile-fixture",
            parent=repository / "fixtures",
        )

        process = self.run_audit(
            repository,
            "--target",
            "repo",
        )

        self.assertEqual(process.returncode, 0)

        payload = json.loads(process.stdout)

        self.assertEqual(payload["targetCount"], 1)
        self.assertEqual(
            Path(payload["results"][0]["skill_directory"]).name,
            "real-skill",
        )

    def test_repository_mode_reports_semantic_batch_limit(self) -> None:
        repository = self.root / "repository"
        skills = repository / "skills"

        for index in range(6):
            self.create_skill(
                f"skill-{index}",
                parent=skills,
            )

        process = self.run_audit(
            repository,
            "--target",
            "repo",
        )

        payload = json.loads(process.stdout)

        self.assertEqual(payload["targetCount"], 6)
        self.assertEqual(payload["semanticBatchLimit"], 5)

    def test_absolute_machine_path_is_a_portability_finding(self) -> None:
        skill = self.create_skill(
            "absolute-path",
            valid_skill(
                "absolute-path",
                body=(
                    "\nRead `/home/developer/project/config.json`.\n"
                ),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            result["readiness_verdict"],
            "Approve with nits",
        )
        self.assertIn(
            "Absolute machine path detected",
            self.finding_titles(result),
        )

    def test_missing_mandatory_alternative_is_major(self) -> None:
        skill = self.create_skill(
            "routing-skill",
            valid_skill(
                "routing-skill",
                description=(
                    "Audit Agent Skills for readiness before release. "
                    "Do not use for security review; use "
                    "skill-security-auditor instead."
                ),
            ),
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertEqual(process.returncode, 1)
        self.assertIn(
            "Description routes to an unavailable mandatory skill",
            self.finding_titles(result),
        )

    def test_installed_mandatory_alternative_resolves(self) -> None:
        skills_root = self.root / "skills"

        self.create_skill(
            "skill-security-auditor",
            parent=skills_root,
        )

        skill = self.create_skill(
            "routing-skill",
            valid_skill(
                "routing-skill",
                description=(
                    "Audit Agent Skills for readiness before release. "
                    "Do not use for security review; use "
                    "skill-security-auditor instead."
                ),
            ),
            parent=skills_root,
        )

        process = self.run_audit(skill)
        result = self.parse_result(process)

        self.assertNotIn(
            "Description routes to an unavailable mandatory skill",
            self.finding_titles(result),
        )

    def test_json_contains_required_security_footer(self) -> None:
        skill = self.create_skill("footer-skill")

        process = self.run_audit(skill)
        payload = json.loads(process.stdout)

        self.assertEqual(
            payload["securityCertification"],
            "Not performed by skill-readiness-auditor.",
        )

    def test_target_scripts_are_not_executed(self) -> None:
        marker = self.root / "should-not-exist"

        skill = self.create_skill(
            "no-execution",
            valid_skill(
                "no-execution",
                allowed_tools="[Read, Bash(bash scripts/dangerous.sh:*)]",
                body=(
                    "\nRun `bash scripts/dangerous.sh target` only during "
                    "the actual skill workflow.\n"
                ),
            ),
        )

        scripts = skill / "scripts"
        scripts.mkdir()

        dangerous = scripts / "dangerous.sh"
        dangerous.write_text(
            (
                "#!/usr/bin/env bash\n"
                f"touch {marker}\n"
            ),
            encoding="utf-8",
        )
        dangerous.chmod(0o755)

        process = self.run_audit(skill)

        self.assertFalse(marker.exists())
        self.assertIn(process.returncode, {0, 1})


if __name__ == "__main__":
    unittest.main()
