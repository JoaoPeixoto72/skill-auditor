#!/usr/bin/env python3
"""Project-policy security audit for local Agent Skills.

Read-only and deterministic: inventories the bundle, classifies external
resources, detects injection, concealment, obfuscation and exfiltration, and
combines the optional SkillSpector evidence into a verdict. The checks live
in `security/`, one module per concern; this file is the entry point the
wrapper and the tests call.
"""

from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
