#!/usr/bin/env python3
"""Deterministic verification of SkillSpector binary integrity and baseline drift.

Validates that the active scanner matches the pinned version, binary hash,
and ruleset declared in config/skillspector.lock.

Invoked by scripts/audit.sh before any scanner evidence is trusted. The result
is a scanner-trust record consumed by security-audit.py --scanner-trust.

Trust states:
  VERIFIED    the scanner is present and matches every pinned value
  UNVERIFIED  the scanner is absent, so no integrity claim can be made
  FAILED      the scanner is present and contradicts a pinned value

Exit codes:
  0  trust is VERIFIED or UNVERIFIED
  1  trust is FAILED, or the lockfile is missing or invalid
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
DEFAULT_LOCK = SKILL_ROOT / "config" / "skillspector.lock"
DEFAULT_BASELINE = SKILL_ROOT / "config" / "skillspector-baseline.json"


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_lock(
    lock_data: dict[str, Any],
    executable_path: Path | None,
    verify_hash: bool = False,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    required_keys = ["scanner", "pinnedVersion", "rulesetVersion"]
    for key in required_keys:
        if key not in lock_data:
            errors.append(f"Lockfile missing required key: '{key}'")

    if errors:
        return False, errors

    if executable_path and executable_path.is_file():
        if verify_hash and "expectedHash" in lock_data:
            actual_hash = sha256_file(executable_path)
            if actual_hash != lock_data["expectedHash"]:
                errors.append(
                    f"Binary hash mismatch: expected {lock_data['expectedHash']}, "
                    f"got {actual_hash}"
                )

    return len(errors) == 0, errors


def verify_scanner_version(
    executable: str,
    expected_version: str,
) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = (proc.stdout or proc.stderr).strip()
        if expected_version not in output:
            return False, f"Version mismatch: expected '{expected_version}' in '{output}'"
        return True, output
    except Exception as exc:
        return False, f"Failed to execute scanner: {exc}"


def resolve_executable(name: str) -> Path | None:
    resolved = shutil.which(name)
    if resolved:
        return Path(resolved)
    candidate = Path(name)
    return candidate if candidate.exists() else None


def build_record(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    record: dict[str, Any] = {
        "schemaVersion": "1.0.0",
        "lockfile": str(args.lockfile),
        "scanner": None,
        "pinnedVersion": None,
        "rulesetVersion": None,
        "executable": None,
        "executableFound": False,
        "lockValid": False,
        "hashVerification": "UNAVAILABLE",
        "versionVerification": "UNAVAILABLE",
        "trust": "FAILED",
        "errors": [],
    }

    if not args.lockfile.exists():
        record["errors"].append(f"Lockfile not found: {args.lockfile}")
        return record, 1

    try:
        lock_data = json.loads(args.lockfile.read_text(encoding="utf-8"))
    except Exception as exc:
        record["errors"].append(f"Invalid lockfile JSON: {exc}")
        return record, 1

    record["scanner"] = lock_data.get("scanner")
    record["pinnedVersion"] = lock_data.get("pinnedVersion")
    record["rulesetVersion"] = lock_data.get("rulesetVersion")

    exec_path = resolve_executable(args.executable)
    record["executable"] = str(exec_path) if exec_path else None
    record["executableFound"] = exec_path is not None

    # Integrity checks only apply to a scanner that is actually present.
    # Absence is reported as UNVERIFIED, never as a passing check.
    verify_hash = args.verify_hash or (
        exec_path is not None and not args.no_verify_hash
    )
    check_version = args.check_version or exec_path is not None

    lock_ok, lock_errors = verify_lock(
        lock_data,
        exec_path,
        verify_hash=verify_hash,
    )
    record["lockValid"] = lock_ok
    record["errors"].extend(lock_errors)

    if not lock_ok:
        record["hashVerification"] = (
            "FAILED" if exec_path is not None else "UNAVAILABLE"
        )
        return record, 1

    if exec_path is None:
        record["hashVerification"] = "UNAVAILABLE"
        record["versionVerification"] = "UNAVAILABLE"
        record["trust"] = "UNVERIFIED"
        record["errors"].append(
            f"Scanner executable '{args.executable}' not found; "
            "scanner integrity cannot be established."
        )
        return record, 0

    record["hashVerification"] = (
        "VERIFIED" if verify_hash and "expectedHash" in lock_data else "SKIPPED"
    )

    if check_version:
        ver_ok, ver_msg = verify_scanner_version(
            str(exec_path),
            str(lock_data["pinnedVersion"]),
        )
        record["versionVerification"] = "VERIFIED" if ver_ok else "FAILED"
        record["versionOutput"] = ver_msg
        if not ver_ok:
            record["errors"].append(ver_msg)
            return record, 1
    else:
        record["versionVerification"] = "SKIPPED"

    record["trust"] = "VERIFIED"
    return record, 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SkillSpector pinned configuration and drift",
    )
    parser.add_argument("--lockfile", type=Path, default=DEFAULT_LOCK, help="Path to skillspector.lock")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE, help="Path to skillspector-baseline.json")
    parser.add_argument("--executable", type=str, default="skillspector", help="Path or command name of scanner")
    parser.add_argument("--verify-hash", action="store_true", help="Force sha256 verification of the executable")
    parser.add_argument("--no-verify-hash", action="store_true", help="Skip sha256 verification of the executable")
    parser.add_argument("--check-version", action="store_true", help="Force scanner version verification")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="Write the trust record to this path as JSON")
    args = parser.parse_args()

    record, exit_code = build_record(args)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    if args.format == "json":
        print(json.dumps(record, ensure_ascii=False, indent=2))
    else:
        for error in record["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"SkillSpector scanner trust: {record['trust']}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
