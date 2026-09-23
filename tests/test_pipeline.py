"""The three owners end to end: readiness, security, release gate.

The path a user takes, with SkillSpector absent — the case the plugin must
support on any machine. The scanner-present path is covered by the security
tests with a recorded SkillSpector report.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "skills"
READINESS = ROOT / "skill-readiness-auditor" / "scripts" / "readiness-audit.py"
SECURITY = ROOT / "skill-security-auditor" / "scripts" / "security-audit.py"
GATE = ROOT / "skill-release-gate" / "scripts" / "release-gate.py"
PAYLOAD = ROOT / "skill-security-auditor" / "tests" / "fixtures" / "concealment-pt.snippet"

SKILL = (
    "---\n"
    "name: notes\n"
    'description: "Summarizes local notes into a changelog. Use when closing a release. '
    'Do not use for code review."\n'
    "allowed-tools: [Read]\n"
    "---\n"
    "# notes\n\n"
    "Read the notes folder and write the summary to the answer.\n"
)


def run(*command: str) -> str:
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, *command], capture_output=True, text=True,
                          encoding="utf-8", env=environment, check=False).stdout


class Pipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.skill = self.root / "notes"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text(SKILL, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def decide(self) -> dict:
        readiness = self.root / "readiness.json"
        security = self.root / "security.json"
        readiness.write_text(run(str(READINESS), str(self.skill), "--format", "json",
                                 "--semantic-complete"), encoding="utf-8")
        security.write_text(run(str(SECURITY), str(self.skill), "--format", "json",
                                "--strict"), encoding="utf-8")
        return json.loads(run(str(GATE), "--readiness-report", str(readiness),
                              "--security-report", str(security), "--action", "install",
                              "--format", "json"))

    def test_clean_skill_is_eligible_without_skillspector(self) -> None:
        self.assertEqual(self.decide()["finalDecision"], "Eligible")

    def test_portuguese_concealment_is_rejected_without_skillspector(self) -> None:
        with (self.skill / "SKILL.md").open("a", encoding="utf-8") as file:
            file.write(PAYLOAD.read_text(encoding="utf-8"))
        self.assertEqual(self.decide()["finalDecision"], "Reject")


if __name__ == "__main__":
    unittest.main()
