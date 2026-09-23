from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "skillspector-adapter.py"


class SkillSpectorAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = self.root / "skill"
        self.target.mkdir()
        (self.target / "SKILL.md").write_text(
            "---\nname: skill\n"
            'description: "Inspect local content."\n'
            "allowed-tools: []\n---\n",
            encoding="utf-8",
        )
        self.output = self.root / "adapter.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_unavailable_scanner_fails_closed(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = str(self.root / "empty-path")
        Path(environment["PATH"]).mkdir()

        process = subprocess.run(
            [
                sys.executable,
                str(ADAPTER),
                str(self.target),
                "--output",
                str(self.output),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        payload = json.loads(
            self.output.read_text(encoding="utf-8")
        )

        self.assertEqual(process.returncode, 1)
        self.assertEqual(payload["status"], "UNAVAILABLE")
        self.assertEqual(payload["completeness"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
