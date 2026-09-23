from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2] / "skills" / "skill-security-auditor"
ADAPTER = ROOT / "scripts" / "skillspector-adapter.py"


def load_adapter():
    import importlib.util
    spec = importlib.util.spec_from_file_location("skillspector_adapter", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_with(exceptions: list[dict], coverage: float = 100.0) -> dict:
    """The SkillSpector 2.x report shape, reduced to what the adapter reads."""
    return {"analysis_completeness": {"is_complete": False, "coverage_percent": coverage,
                                      "ledger_exceptions": exceptions}}


class ScanViewTests(unittest.TestCase):
    def test_ignored_bytecode_is_not_in_the_distributed_view(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
            (root / "tool.py").write_text("print(1)\n", encoding="utf-8")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "tool.cpython-314.pyc").write_bytes(b"\x00")
            files = load_adapter().distributed_files(root)
        self.assertIn("tool.py", files)
        self.assertFalse([name for name in files if name.endswith(".pyc")], files)

    def test_outside_git_the_whole_directory_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            view, kind = load_adapter().scan_view(Path(tmp), Path(tmp))
        self.assertEqual(kind, "directory")


class CompletenessTests(unittest.TestCase):
    missing = {"reason_code": "reference_missing", "fatal": False}

    def test_only_missing_references_count_as_complete(self) -> None:
        self.assertEqual(load_adapter().infer_completeness(report_with([self.missing])), "COMPLETE")

    def test_a_parse_error_stays_partial(self) -> None:
        parse = {"reason_code": "manifest_parse_error", "fatal": False}
        self.assertEqual(load_adapter().infer_completeness(report_with([self.missing, parse])), "PARTIAL")

    def test_restated_gap_is_not_a_finding(self) -> None:
        issues = [{"id": "AE1", "severity": "HIGH"}, {"id": "AST8", "severity": "CRITICAL"}]
        split = load_adapter().separate_restated_gaps
        kept, restated, _ = split(issues, report_with([self.missing])["analysis_completeness"])
        self.assertEqual(([f["id"] for f in kept], [f["id"] for f in restated]), (["AST8"], ["AE1"]))
        parse = {"reason_code": "manifest_parse_error", "fatal": False}
        kept, _, _ = split(issues, report_with([self.missing, parse])["analysis_completeness"])
        self.assertEqual([f["id"] for f in kept], ["AE1", "AST8"])

    def test_uninspected_content_stays_partial(self) -> None:
        self.assertEqual(load_adapter().infer_completeness(report_with([self.missing], 80.0)), "PARTIAL")


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

    def test_unavailable_scanner_is_recorded_not_fatal(self) -> None:
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

        self.assertEqual(process.returncode, 0)
        self.assertEqual(payload["status"], "UNAVAILABLE")
        self.assertEqual(payload["completeness"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
