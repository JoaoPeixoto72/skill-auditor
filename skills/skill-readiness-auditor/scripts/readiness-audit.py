#!/usr/bin/env python3
"""Deterministic mechanical readiness auditor for Agent Skills.

This program is read-only. It evaluates structural readiness, local-resource
resolution, permission-command coherence, basic trigger quality, portability,
and security-handoff signals.

It does not certify security and does not execute target scripts. The checks
live in `readiness/`, one module per concern; this file is the entry point the
wrapper and the tests call.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Reports contain `·` and `§`. Redirected stdout defaults to the system locale
# on Windows, which writes cp1252 bytes that skill-release-gate cannot decode.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from readiness.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
