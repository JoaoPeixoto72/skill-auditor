"""The exec guard: during an audit, the audited code does not run."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[2] / "hooks"
ROOT = HOOKS.parent


def load_guard():
    sys.path.insert(0, str(HOOKS))
    spec = importlib.util.spec_from_file_location("exec_guard", HOOKS / "exec_guard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def skill_call(name: str) -> dict:
    return {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "name": "Skill", "input": {"skill": name}}]}}


def prompt(text: str) -> dict:
    return {"type": "user", "message": {"role": "user", "content": text}}


class BlockedReason(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = load_guard()
        self.own = str(ROOT / "skills" / "skill-security-auditor" / "scripts" / "audit.sh")

    def test_target_scripts_are_blocked(self) -> None:
        for command in ("bash target/scripts/install.sh", "python3 target/x.py --help",
                        "python -m target_pkg", "node target/index.js", "source target/env.sh",
                        ". target/env.sh", "./target/run", "target/scripts/run.sh --dry",
                        "npm test", "npx some-tool", "make all", "pytest target",
                        "pip install -r target/requirements.txt", "uv run target/x.py",
                        "cd target && npm run build", "echo ok; bash x.sh",
                        "FOO=1 python target/x.py", "pwsh target/x.ps1"):
            with self.subTest(command=command):
                self.assertIsNotNone(self.guard.blocked_reason(command))

    def test_reading_and_own_wrappers_are_allowed(self) -> None:
        for command in (f'bash "{self.own}" target --strict --format json',
                        f"bash {self.own} target", "find target -type f", "wc -l target/SKILL.md",
                        "file target/bin/tool", "grep -rn curl target", "git -C target ls-files",
                        "python -c \"import json,sys; print(json.load(sys.stdin)['verdict'])\"",
                        "cat target/scripts/install.sh", "test -f target/SKILL.md"):
            with self.subTest(command=command):
                self.assertIsNone(self.guard.blocked_reason(command))

    def test_a_copy_of_the_wrapper_inside_the_target_is_not_ours(self) -> None:
        fake = "/tmp/evil/skills/skill-security-auditor/scripts/audit.sh"
        self.assertIsNotNone(self.guard.blocked_reason(f"bash {fake} ."))


class HookProtocol(unittest.TestCase):
    """Driven through stdin and the exit code, as Claude Code runs it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.transcript = Path(self.tmp.name) / "t.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_hook(self, records: list[dict], command: str) -> subprocess.CompletedProcess[str]:
        self.transcript.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        event = {"tool_name": "Bash", "tool_input": {"command": command},
                 "transcript_path": str(self.transcript), "cwd": self.tmp.name}
        return subprocess.run([sys.executable, str(HOOKS / "exec_guard.py")], input=json.dumps(event),
                              capture_output=True, text=True, encoding="utf-8", check=False)

    def test_blocks_with_exit_2_during_an_audit(self) -> None:
        done = self.run_hook([prompt("audit ./target"), skill_call("skill-auditor:skill-security-auditor")],
                             "bash target/scripts/install.sh")
        self.assertEqual(done.returncode, 2)
        self.assertIn("skill-security-auditor", done.stderr)

    def test_silent_outside_an_audit(self) -> None:
        done = self.run_hook([prompt("run the tests"), skill_call("other-skill")], "npm test")
        self.assertEqual((done.returncode, done.stderr), (0, ""))

    def test_an_audit_in_an_earlier_turn_does_not_count(self) -> None:
        done = self.run_hook([prompt("audit"), skill_call("skill-readiness-auditor"), prompt("now build")],
                             "npm run build")
        self.assertEqual(done.returncode, 0)

    def test_other_tools_pass(self) -> None:
        self.transcript.write_text(json.dumps(skill_call("skill-security-auditor")) + "\n", encoding="utf-8")
        event = {"tool_name": "Read", "tool_input": {"file_path": "x"}, "transcript_path": str(self.transcript)}
        done = subprocess.run([sys.executable, str(HOOKS / "exec_guard.py")], input=json.dumps(event),
                              capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(done.returncode, 0)


class Registered(unittest.TestCase):
    def test_hooks_json_runs_the_guard_on_bash(self) -> None:
        config = json.loads((HOOKS / "hooks.json").read_text(encoding="utf-8"))
        commands = [h["command"] for group in config["hooks"]["PreToolUse"] if "Bash" in group["matcher"]
                    for h in group["hooks"]]
        self.assertTrue(any("exec-guard.sh" in c for c in commands))


if __name__ == "__main__":
    unittest.main()
