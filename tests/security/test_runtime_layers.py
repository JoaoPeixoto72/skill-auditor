"""Which runtime layer can vouch for a skill whose script reaches the network.

A PreToolUse hook sees tool calls; a script's own requests only the OS sandbox
(strict mode) or a disposable cloud environment with an allowlist can confine
(Claude Code best practices; Lydia Hallie, "Rethinking Claude Code best
practices", 2026-11).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

AUDITOR = Path(__file__).resolve().parents[2] / "skills" / "skill-security-auditor" / "scripts" / "security-audit.py"
FULL = {"directEgressBlocked": True, "bundleIntegrityEnabled": True, "quarantineRevocationEnabled": True}


class RuntimeLayers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.skill = Path(self.tmp.name) / "status"
        (self.skill / "scripts").mkdir(parents=True)
        (self.skill / "SKILL.md").write_text(
            '---\nname: status\ndescription: "Reports service status. Use when asked whether the API is up."\n'
            "allowed-tools: [Read]\n---\n# status\nRun `python scripts/get.py`.\n", encoding="utf-8")
        (self.skill / "scripts" / "get.py").write_text(
            "import urllib.request\nprint(urllib.request.urlopen(URL).status)\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, attestation: dict | None = None) -> dict:
        args = [sys.executable, str(AUDITOR), str(self.skill), "--format", "json"]
        if attestation is not None:
            path = Path(self.tmp.name) / "attestation.json"
            path.write_text(json.dumps(attestation), encoding="utf-8")
            args += ["--runtime-attestation", str(path)]
        done = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", check=False)
        return json.loads(done.stdout)["results"][0]

    def test_standard_library_request_is_network_capability(self) -> None:
        result = self.audit()
        self.assertTrue(result["networkCapable"])
        self.assertTrue(result["requiresRuntimeGate"])

    def test_strict_sandbox_counts_as_enforcement(self) -> None:
        result = self.audit({**FULL, "enforcedControls": ["os-sandbox-strict"]})
        self.assertEqual(result["runtimeEnforcement"], "VERIFIED")

    def test_cloud_allowlist_counts_as_enforcement(self) -> None:
        result = self.audit({**FULL, "enforcedControls": ["cloud-network-allowlist"]})
        self.assertEqual(result["runtimeEnforcement"], "VERIFIED")

    def test_a_tool_call_hook_alone_does_not(self) -> None:
        result = self.audit({**FULL, "enforcedControls": ["pretooluse-link-guard"]})
        self.assertEqual(result["runtimeEnforcement"], "UNVERIFIED")

    def test_host_interception_still_counts(self) -> None:
        result = self.audit({**FULL, "networkInterceptionEnabled": True})
        self.assertEqual(result["runtimeEnforcement"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
