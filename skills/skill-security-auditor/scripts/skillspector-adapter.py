#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_help(executable: str) -> str:
    process = subprocess.run(
        [executable, "scan", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return f"{process.stdout}\n{process.stderr}"


def scanner_version(executable: str) -> str:
    process = subprocess.run(
        [executable, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    value = (process.stdout or process.stderr).strip()
    return value or "unknown"


def extract_findings(report: Any) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return []

    candidates = [
        report.get("findings"),
        report.get("results"),
        report.get("issues"),
    ]

    for candidate in candidates:
        if isinstance(candidate, list):
            return [
                item
                for item in candidate
                if isinstance(item, dict)
            ]

    runs = report.get("runs")
    if isinstance(runs, list):
        findings: list[dict[str, Any]] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            results = run.get("results")
            if isinstance(results, list):
                findings.extend(
                    item
                    for item in results
                    if isinstance(item, dict)
                )
        return findings

    return []


# A reference to a file the bundle does not ship (a project script, a file the
# skill writes at runtime) leaves nothing inside the bundle uninspected.
BENIGN_GAPS = {"reference_missing"}


def accepted_gaps(analysis: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The ledger exceptions, when every one of them is a benign gap."""
    exceptions = analysis.get("ledger_exceptions") or []
    if analysis.get("coverage_percent", 0) < 100:
        return None
    if all(
        isinstance(item, dict)
        and not item.get("fatal")
        and item.get("reason_code") in BENIGN_GAPS
        for item in exceptions
    ):
        return exceptions
    return None


def distributed_files(target: Path) -> list[str] | None:
    """Files git would distribute from `target`, or None outside a work tree.

    A local `__pycache__` or build output is ignored by git and never ships;
    a `.pyc` that is committed does ship, and stays in the scanned view.
    """
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."],
            cwd=target, capture_output=True, check=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return [name for name in listing.stdout.decode("utf-8").split("\0") if name]


def scan_view(target: Path, scratch: Path) -> tuple[Path, str]:
    """The directory SkillSpector reads: the distributed bundle when git knows it."""
    files = distributed_files(target) if target.is_dir() else None
    if files is None:
        return target, "directory"
    view = scratch / "bundle" / target.name
    for name in files:
        source = target / name
        if source.is_file():
            destination = view / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    return view, "git-distributed-files"


def infer_completeness(report: Any) -> str:
    if not isinstance(report, dict):
        return "FAILED"

    analysis = report.get("analysis_completeness")

    if isinstance(analysis, dict):
        if analysis.get("is_complete") is True:
            return "COMPLETE"
        if analysis.get("is_complete") is False:
            return "COMPLETE" if accepted_gaps(analysis) is not None else "PARTIAL"

    for key in ("complete", "is_complete", "analysis_complete"):
        if report.get(key) is True:
            return "COMPLETE"
        if report.get(key) is False:
            return "PARTIAL"

    status = str(report.get("status", "")).lower()

    if status in {"complete", "completed", "success", "passed"}:
        return "COMPLETE"

    if status in {"partial", "incomplete"}:
        return "PARTIAL"

    return "COMPLETE"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    target = Path(args.target).resolve()
    output = Path(args.output).resolve()

    if not target.exists():
        write_result(output, {
            "adapterVersion": "1.0.0",
            "status": "FAILED",
            "completeness": "FAILED",
            "error": f"Target does not exist: {target}",
            "findings": [],
        })
        return 1

    executable = shutil.which("skillspector")

    if executable is None:
        write_result(output, {
            "adapterVersion": "1.0.0",
            "status": "UNAVAILABLE",
            "completeness": "UNAVAILABLE",
            "scannerVersion": None,
            "error": "skillspector executable not found",
            "findings": [],
        })
        # Optional scanner: its absence is a recorded state, not a failure.
        return 0

    try:
        help_text = parse_help(executable)
        version = scanner_version(executable)
    except Exception as error:
        write_result(output, {
            "adapterVersion": "1.0.0",
            "status": "FAILED",
            "completeness": "FAILED",
            "scannerVersion": None,
            "error": str(error),
            "findings": [],
        })
        return 1

    supported_flags: list[str] = []
    omitted_flags: list[str] = []

    for flag in ("--fail-on-findings", "--fail-on-incomplete"):
        if flag in help_text:
            supported_flags.append(flag)
        else:
            omitted_flags.append(flag)

    with tempfile.TemporaryDirectory(
        prefix="skillspector-adapter-"
    ) as directory:
        raw_report_path = Path(directory) / "report.json"
        scanned, view = scan_view(target, Path(directory))

        command = [
            executable,
            "scan",
            str(scanned),
            "--no-llm",
            "--format",
            "json",
            "--output",
            str(raw_report_path),
            *supported_flags,
        ]

        try:
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=660,
            )
        except subprocess.TimeoutExpired:
            write_result(output, {
                "adapterVersion": "1.0.0",
                "status": "FAILED",
                "completeness": "FAILED",
                "scannerVersion": version,
                "command": command,
                "error": "SkillSpector timed out",
                "findings": [],
                "omittedStrictFlags": omitted_flags,
            })
            return 1
        except Exception as error:
            write_result(output, {
                "adapterVersion": "1.0.0",
                "status": "FAILED",
                "completeness": "FAILED",
                "scannerVersion": version,
                "command": command,
                "error": str(error),
                "findings": [],
                "omittedStrictFlags": omitted_flags,
            })
            return 1

        if not raw_report_path.is_file():
            write_result(output, {
                "adapterVersion": "1.0.0",
                "status": "FAILED",
                "completeness": "FAILED",
                "scannerVersion": version,
                "command": command,
                "exitCode": process.returncode,
                "stdout": process.stdout[-4000:],
                "stderr": process.stderr[-4000:],
                "error": "SkillSpector did not produce a JSON report",
                "findings": [],
                "omittedStrictFlags": omitted_flags,
            })
            return 1

        try:
            raw_report = json.loads(
                raw_report_path.read_text(encoding="utf-8")
            )
        except Exception as error:
            write_result(output, {
                "adapterVersion": "1.0.0",
                "status": "FAILED",
                "completeness": "FAILED",
                "scannerVersion": version,
                "command": command,
                "exitCode": process.returncode,
                "error": f"Invalid SkillSpector JSON: {error}",
                "findings": [],
                "omittedStrictFlags": omitted_flags,
            })
            return 1

    completeness = infer_completeness(raw_report)
    findings = extract_findings(raw_report)
    # SkillSpector 2.x nests its verdict under `risk_assessment`.
    raw_report = raw_report if isinstance(raw_report, dict) else {}
    risk = raw_report.get("risk_assessment") or {}
    analysis = raw_report.get("analysis_completeness")

    normalized = {
        "adapterVersion": "1.0.0",
        "status": (
            "COMPLETE"
            if completeness == "COMPLETE"
            else completeness
        ),
        "completeness": completeness,
        "scannerVersion": version,
        "command": command,
        "scannedView": view,
        "exitCode": process.returncode,
        "supportedStrictFlags": supported_flags,
        "omittedStrictFlags": omitted_flags,
        "riskScore": risk.get("score", raw_report.get("risk_score")),
        "recommendation": risk.get("recommendation", raw_report.get("recommendation")),
        "acceptedGaps": (
            accepted_gaps(analysis) or []
            if isinstance(analysis, dict) and analysis.get("is_complete") is False
            else []
        ),
        "findings": findings,
        "rawReport": raw_report,
    }

    write_result(output, normalized)

    return 0 if completeness == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
