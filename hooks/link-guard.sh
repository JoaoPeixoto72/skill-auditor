#!/usr/bin/env bash
# skill-auditor link guard: PreToolUse entry point (hooks/hooks.json).
# Resolves a Python that actually runs (the Windows Store alias does not) and
# hands it the hook's stdin. Without Python it says so and lets the call
# through: blocking every Bash command would be worse than an absent guard.
export PYTHONIOENCODING=utf-8 PYTHONUTF8=1
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    exec "$candidate" "$HERE/link_guard.py"
  fi
done
echo "skill-auditor link guard: no working Python; links are not being checked." >&2
exit 0
