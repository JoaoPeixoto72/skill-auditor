#!/usr/bin/env bash
# skill-readiness-auditor · deterministic mechanical entry point
# Read-only.
#
# Usage:
#   bash scripts/audit.sh <skill-path-or-repo>
#   bash scripts/audit.sh <skill-path-or-repo> --format json
#   bash scripts/audit.sh <skill-path-or-repo> --json

set -euo pipefail
export LC_ALL=C
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

resolve_python() {
  local candidate

  for candidate in python3 python py; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi

    if "$candidate" -c "import sys, yaml" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

PYTHON_BIN="$(resolve_python || true)"

if [[ -z "$PYTHON_BIN" ]]; then
  cat >&2 <<'EOF'
Error: skill-readiness-auditor requires Python with PyYAML.

Install PyYAML in the active environment, for example:
  python3 -m pip install PyYAML
EOF
  exit 2
fi

if [[ ! -f "$SCRIPT_DIR/readiness-audit.py" ]]; then
  echo "Error: missing implementation: $SCRIPT_DIR/readiness-audit.py" >&2
  exit 2
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/readiness-audit.py" "$@"
