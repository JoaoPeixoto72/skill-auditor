#!/usr/bin/env bash
# skill-release-gate · deterministic decision entry point
# Read-only. Never mutates the Trust Registry, signs, installs, or enrols.
#
# Usage:
#   bash scripts/gate.sh --readiness-report <json> --security-report <json> --action <action>
#
# Exit codes:
#   0  decision is "Eligible"
#   1  any other decision
#   2  the gate could not run (missing interpreter or implementation)

set -euo pipefail
export LC_ALL=C
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# `command -v python3` is not sufficient on Windows: the App Execution Alias
# resolves successfully but exits with an error instead of running Python.
resolve_python() {
  local candidate

  for candidate in python3 python py; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi

    if "$candidate" -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

PYTHON_BIN="$(resolve_python || true)"

if [[ -z "$PYTHON_BIN" ]]; then
  cat >&2 <<'EOF'
Error: skill-release-gate requires a working Python 3 interpreter.

None of python3, python, or py could execute. On Windows, a `python3` that
prints "Python was not found" is the Microsoft Store alias, not an interpreter.
EOF
  exit 2
fi

if [[ ! -f "$SCRIPT_DIR/release-gate.py" ]]; then
  echo "Error: missing implementation: $SCRIPT_DIR/release-gate.py" >&2
  exit 2
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/release-gate.py" "$@"
