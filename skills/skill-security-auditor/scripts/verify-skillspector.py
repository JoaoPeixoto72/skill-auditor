#!/usr/bin/env python3
"""Scanner-trust record for the optional NVIDIA SkillSpector.

SkillSpector is installed with `uv tool install` from its git repository; the
executable is a per-machine shim, so a hash of it proves nothing and the
project publishes no scanner signature. What can be checked is that the
scanner is the one the adapter understands: its version is at least the
`minimumVersion` in config/skillspector.lock (the 2.x report shape).

Trust states:
  VERIFIED     present, and its version meets the minimum
  UNAVAILABLE  not installed — the audit runs on the project-policy line alone
  FAILED       present but its version is unreadable or below the minimum,
               or the lockfile is invalid

Exit code: 1 only for FAILED.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_LOCK = Path(__file__).resolve().parent.parent / "config" / "skillspector.lock"
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(text)
    return tuple(int(part) for part in match.groups()) if match else None


def installed_version(executable: str) -> str:
    process = subprocess.run([executable, "--version"], capture_output=True,
                             text=True, timeout=60, check=False)
    return (process.stdout or process.stderr).strip()


def build_record(lockfile: Path, executable_name: str) -> dict[str, Any]:
    record: dict[str, Any] = {"lockfile": str(lockfile), "executable": None,
                              "minimumVersion": None, "installedVersion": None,
                              "trust": "FAILED", "errors": []}
    try:
        lock = json.loads(lockfile.read_text(encoding="utf-8"))
        minimum = parse_version(str(lock["minimumVersion"]))
        record["minimumVersion"] = lock["minimumVersion"]
    except (OSError, ValueError, KeyError) as error:
        record["errors"].append(f"Invalid lockfile: {error}")
        return record
    executable = shutil.which(executable_name)
    if executable is None:
        record["trust"] = "UNAVAILABLE"
        return record
    record["executable"] = executable
    try:
        version_text = installed_version(executable)
    except (OSError, subprocess.TimeoutExpired) as error:
        record["errors"].append(f"Cannot read scanner version: {error}")
        return record
    record["installedVersion"] = version_text
    version = parse_version(version_text)
    if version is None or minimum is None or version < minimum:
        record["errors"].append(f"SkillSpector {version_text!r} is below {lock['minimumVersion']}")
        return record
    record["trust"] = "VERIFIED"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lockfile", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--executable", default="skillspector")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    record = build_record(args.lockfile, args.executable)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.format == "json":
        print(json.dumps(record, ensure_ascii=False, indent=2))
    else:
        for error in record["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"SkillSpector scanner trust: {record['trust']}")
    return 1 if record["trust"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
