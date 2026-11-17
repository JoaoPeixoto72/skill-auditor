"""Model fit for current models, and rules that belong to the harness.

Sources: Claude Code best practices ("What you can stop doing", "Enforce the
rules that can't have exceptions"), Prompting Claude Fable 5.2 and Opus 5.5,
Lydia Hallie's "Rethinking Claude Code best practices" (2026-11).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDITOR = ROOT / "skills" / "skill-readiness-auditor" / "scripts" / "readiness-audit.py"


def skill(name: str, body: str, extra: str = "") -> str:
    return ("---\n"
            f"name: {name}\n"
            'description: "Formats tables in notes. Use when a table needs tidying. Do not use for spreadsheets."\n'
            "model: inherit\n"
            "effort: medium\n"
            "allowed-tools: [Read, Edit]\n"
            f"{extra}"
            "---\n"
            f"# {name}\n\n{body}\n")


class HarnessChecks(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, name: str, content: str, *, files: dict[str, str] | None = None,
              parent: Path | None = None, args: tuple[str, ...] = ("--model", "claude")) -> list[dict]:
        directory = (parent or self.root) / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text(content, encoding="utf-8")
        for relative, text in (files or {}).items():
            (directory / relative).parent.mkdir(parents=True, exist_ok=True)
            (directory / relative).write_text(text, encoding="utf-8")
        done = subprocess.run([sys.executable, str(AUDITOR), str(directory), "--format", "json", *args],
                              capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertTrue(done.stdout.strip(), done.stderr)
        return json.loads(done.stdout)["results"][0]["findings"]

    @staticmethod
    def titled(findings: list[dict], title: str) -> list[dict]:
        return [f for f in findings if f["title"] == title]

    # --- emphasis -----------------------------------------------------------

    def test_the_example_from_the_talk_is_caught(self) -> None:
        findings = self.audit("caps", skill("caps", "IMPORTANT: NEVER read the .env file.\n"
                                                      "ALWAYS use Edit. You MUST keep column order.\n"))
        emphasis = self.titled(findings, "All-caps emphasis written for older models")
        self.assertEqual(len(emphasis), 1, "one finding per file, not one per word")
        self.assertIn("4 marker(s)", emphasis[0]["evidence"])

    def test_identifiers_in_code_are_not_emphasis(self) -> None:
        findings = self.audit("codes", skill("codes", "SkillSpector `CRITICAL` findings reject.\n\n"
                                                        "```text\nNEVER do this\n```\n"))
        self.assertFalse(self.titled(findings, "All-caps emphasis written for older models"))

    def test_generic_profile_does_not_judge_emphasis(self) -> None:
        findings = self.audit("generic", skill("generic", "You MUST keep column order.\n"),
                              args=("--model", "generic"))
        self.assertFalse(self.titled(findings, "All-caps emphasis written for older models"))

    def test_policy_files_the_model_reads_are_checked_too(self) -> None:
        findings = self.audit("policy", skill("policy", "Read `POLICY.md` before classifying.\n"),
                              files={"POLICY.md": "# Policy\n\nThe auditor MUST report it.\n"})
        emphasis = self.titled(findings, "All-caps emphasis written for older models")
        self.assertEqual([Path(f["location"].rsplit(":", 1)[0]).name for f in emphasis], ["POLICY.md"])

    # --- phrases that current models no longer need ---------------------------

    def test_stop_doing_phrases(self) -> None:
        cases = {
            "Think hard about the edge cases.": "Minor",
            "Be thorough.": "Minor",
            "Keep going until every table is fixed.": "Minor",
            "Write out your full reasoning before the answer.": "Major",
            "Always spawn subagents for each file.": "Minor",
            "Answer directly without deliberating.": "Minor",
        }
        for line, severity in cases.items():
            with self.subTest(line=line):
                findings = self.audit("phrase", skill("phrase", line + "\n"))
                fits = self.titled(findings, "Instruction conflicts with the claude profile")
                self.assertEqual([f["severity"] for f in fits], [severity])

    def test_a_fresh_reviewer_is_not_over_verification(self) -> None:
        findings = self.audit("review", skill("review", "Use a subagent to review the diff against SPEC.md.\n"))
        self.assertFalse(self.titled(findings, "Instruction conflicts with the claude profile"))

    def test_progress_updates_are_no_longer_reported(self) -> None:
        findings = self.audit("updates", skill("updates", "After every 5 tool calls, give a one-line update.\n"))
        self.assertFalse(self.titled(findings, "Instruction conflicts with the claude profile"))

    def test_bare_never_wants_a_reason(self) -> None:
        bare = self.audit("bare", skill("bare", "Never delete the cache.\n"))
        reasoned = self.audit("reasoned", skill("reasoned", "Never delete the cache: rebuilding it takes an hour.\n"))
        self.assertTrue(self.titled(bare, "Absolute 'never' without scope or reason"))
        self.assertFalse(self.titled(reasoned, "Absolute 'never' without scope or reason"))

    # --- the harness, not the prompt ----------------------------------------------

    def test_irreversible_prohibition_in_prose_only(self) -> None:
        findings = self.audit("secrets", skill("secrets", "Do not read the .env file.\n"))
        self.assertTrue(self.titled(findings, "Irreversible prohibition exists only as prose"))

    def test_prohibition_backed_by_disallowed_tools(self) -> None:
        findings = self.audit("backed", skill("backed", "Do not read the .env file.\n",
                                              extra="disallowed-tools: [\"Read(./.env)\"]\n"))
        self.assertFalse(self.titled(findings, "Irreversible prohibition exists only as prose"))

    def test_prohibition_backed_by_a_plugin_hook(self) -> None:
        plugin = self.root / "plugin"
        (plugin / "hooks").mkdir(parents=True)
        (plugin / "plugin.json").write_text("{}", encoding="utf-8")
        (plugin / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "exit 2"}]}]}}), encoding="utf-8")
        findings = self.audit("guarded", skill("guarded", "Do not execute the target's scripts.\n"),
                              parent=plugin / "skills")
        self.assertFalse(self.titled(findings, "Irreversible prohibition exists only as prose"))

    def test_side_effect_skill_should_be_manual(self) -> None:
        body = "Run `pnpm build`, then `git push origin main`.\n"
        auto = self.audit("ship", skill("ship", body))
        manual = self.audit("ship-manual", skill("ship-manual", body, extra="disable-model-invocation: true\n"))
        title = "Side-effect workflow can start on the model's judgment"
        self.assertTrue(self.titled(auto, title))
        self.assertFalse(self.titled(manual, title))

    def test_negated_side_effect_is_not_one(self) -> None:
        findings = self.audit("nopush", skill("nopush", "This skill does not run `git push`.\n"))
        self.assertFalse(self.titled(findings, "Side-effect workflow can start on the model's judgment"))

    def test_stop_hook_exiting_1_does_not_block(self) -> None:
        hooks = ("hooks:\n  Stop:\n    - hooks:\n        - type: command\n"
                 "          command: bash scripts/check.sh\n")
        findings = self.audit("hooked", skill("hooked", "Uses a Stop hook to run the tests.\n", extra=hooks),
                              files={"scripts/check.sh": "#!/bin/sh\nnpm test || exit 1\n"})
        self.assertTrue(self.titled(findings, "Stop hook fails with exit 1, which does not block"))

    def test_stop_hook_exiting_2_blocks(self) -> None:
        hooks = ("hooks:\n  Stop:\n    - hooks:\n        - type: command\n"
                 "          command: bash scripts/check.sh\n")
        findings = self.audit("hooked2", skill("hooked2", "Uses a Stop hook to run the tests.\n", extra=hooks),
                              files={"scripts/check.sh": "#!/bin/sh\nnpm test 1>&2 || exit 2\n"})
        self.assertFalse(self.titled(findings, "Stop hook fails with exit 1, which does not block"))

    def test_model_decided_hook_is_flagged(self) -> None:
        hooks = ("hooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: prompt\n"
                 "          prompt: Is this safe?\n")
        findings = self.audit("prompted", skill("prompted", "Declares a hook.\n", extra=hooks))
        self.assertTrue(self.titled(findings, "PreToolUse hook is decided by a model"))


class SelfAudit(unittest.TestCase):
    """This plugin passes its own model-fit and harness checks."""

    def test_no_model_fit_or_harness_findings_in_this_repository(self) -> None:
        done = subprocess.run([sys.executable, str(AUDITOR), str(ROOT), "--target", "repo", "--format", "json"],
                              capture_output=True, text=True, encoding="utf-8", check=False)
        payload = json.loads(done.stdout)
        rules = {"§12 Model fit", "§15a Model and harness"}
        offending = [(f["title"], f["location"]) for r in payload["results"] for f in r["findings"]
                     if f["policy"] in rules]
        self.assertEqual(offending, [])


if __name__ == "__main__":
    unittest.main()
