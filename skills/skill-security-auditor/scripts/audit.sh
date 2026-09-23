#!/usr/bin/env bash
# skill-security-auditor · deterministic security entry point
# Read-only. Never executes, installs, or fetches anything from the target.
#
# Usage:
#   bash scripts/audit.sh <local-target> [--strict] [--format markdown|json|sarif]
#   bash scripts/audit.sh <local-target> --target-mode repo
#
# Exit codes:
#   0  security verdict is "Eligible for enrolment"
#   1  audit completed with a non-eligible verdict
#   2  the audit could not run (missing interpreter, bad target, scanner integrity failure)

set -u
set -o pipefail
export LC_ALL=C
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: bash scripts/audit.sh <local-target> [options]" >&2
  exit 2
fi

case "$TARGET" in
  http://*|https://*|git://*|ssh://*)
    echo "Error: only local targets are accepted." >&2
    exit 2
    ;;
esac

shift

# Resolve an interpreter that actually runs.
#
# `command -v python3` is not sufficient on Windows: the App Execution Alias
# installs a stub that resolves successfully but exits with an error message
# instead of running Python. Probe each candidate by executing it.
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
Error: skill-security-auditor requires a working Python 3 interpreter.

None of python3, python, or py could execute. On Windows, a `python3` that
prints "Python was not found" is the Microsoft Store alias, not an interpreter.
Install Python 3, or disable the alias under
Settings > Apps > Advanced app settings > App execution aliases.
EOF
  exit 2
fi

for required in security-audit.py skillspector-adapter.py verify-skillspector.py; do
  if [[ ! -f "$SCRIPT_DIR/$required" ]]; then
    echo "Error: missing implementation: $SCRIPT_DIR/$required" >&2
    exit 2
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/skill-security-audit.XXXXXX")" || {
  echo "Error: could not create a temporary directory." >&2
  exit 2
}
trap 'rm -rf "$TMP_DIR"' EXIT

SCANNER_REPORT="$TMP_DIR/skillspector.json"
SCANNER_TRUST="$TMP_DIR/skillspector-trust.json"

# Scanner supply chain: verify the pinned SkillSpector version and ruleset
# declared in config/skillspector.lock before any scanner evidence is trusted.
# A failure here never aborts the audit; it downgrades scanner trust, which the
# project-policy audit records and folds into the verdict.
"$PYTHON_BIN" "$SCRIPT_DIR/verify-skillspector.py" \
  --format json \
  --output "$SCANNER_TRUST" >/dev/null 2>&1
TRUST_EXIT=$?

"$PYTHON_BIN" "$SCRIPT_DIR/skillspector-adapter.py" \
  "$TARGET" \
  --output "$SCANNER_REPORT"
ADAPTER_EXIT=$?

"$PYTHON_BIN" "$SCRIPT_DIR/security-audit.py" \
  "$TARGET" \
  --skillspector-report "$SCANNER_REPORT" \
  --scanner-trust "$SCANNER_TRUST" \
  "$@"
AUDIT_EXIT=$?

if [[ "$AUDIT_EXIT" -ne 0 ]]; then
  exit "$AUDIT_EXIT"
fi

if [[ "$ADAPTER_EXIT" -ne 0 || "$TRUST_EXIT" -ne 0 ]]; then
  exit 1
fi

exit 0
