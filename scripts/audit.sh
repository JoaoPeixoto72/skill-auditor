#!/usr/bin/env bash
# skill-auditor · mechanical linter
# Read-only. Emits deterministic findings with Confidence: Observed.
# Usage: bash scripts/audit.sh <skill-path-or-repo>

set -euo pipefail

TARGET="${1:-.}"
FAIL=0
FINDINGS=()

emit() {
  local sev="$1" ; shift
  local msg="$*"
  FINDINGS+=("[${sev}] ${msg}")
  [ "$sev" = "Blocker" ] || [ "$sev" = "Major" ] && FAIL=1 || true
}

check_skill() {
  local skill_md="$1"
  local dir
  dir="$(dirname "$skill_md")"
  local folder
  folder="$(basename "$dir")"

  # §1. Frontmatter
  if ! head -n 1 "$skill_md" | grep -q '^---$'; then
    emit Blocker "$skill_md: no YAML frontmatter on line 1"
    return
  fi

  # Extract frontmatter
  local fm
  fm="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$skill_md")"

  # name matches folder
  local name
  name="$(echo "$fm" | awk -F': *' '/^name:/{print $2; exit}')"
  if [ -z "$name" ]; then
    emit Blocker "$skill_md: frontmatter has no 'name' field"
  elif [ "$name" != "$folder" ]; then
    emit Major "$skill_md: name='$name' does not match folder='$folder'"
  fi

  # description present
  if ! echo "$fm" | grep -q '^description:'; then
    emit Blocker "$skill_md: frontmatter has no 'description'"
  fi

  # allowed-tools present (may be empty, but the field must exist)
  if ! echo "$fm" | grep -q '^allowed-tools:'; then
    emit Minor "$skill_md: no 'allowed-tools' declared"
  fi

  # §4. Referenced resources exist
  local refs
  refs="$(grep -oE '(references|scripts)/[A-Za-z0-9_.-]+' "$skill_md" | sort -u || true)"
  local ref
  for ref in $refs; do
    if [ ! -e "$dir/$ref" ]; then
      emit Blocker "$skill_md: references '$ref' but the file does not exist in $dir/"
    fi
  done

  # §5. Scripts outside the skill folder
  if grep -qE 'bash +\.\./|bash +/' "$skill_md"; then
    emit Major "$skill_md: invokes a script outside the skill folder (absolute path or ../)"
  fi

  # §7. Anti-injection statement in a skill that processes external content
  # Heuristic: audit/lint/summariz skills, or a skill whose description mentions
  # "audits", "reviews", "summarizes", "extracts". `ux-review` is a scope router,
  # it does not process external artifacts as instructions — excluded explicitly.
  local needs_injection_stmt=0
  if echo "$name" | grep -qiE '^(skill-)?(audit|lint|summariz)'; then
    needs_injection_stmt=1
  elif [ "$name" != "ux-review" ] && echo "$fm" | grep -qiE 'description:.*\b(audits|reviews an?|summariz|extracts from)\b'; then
    needs_injection_stmt=1
  fi
  if [ "$needs_injection_stmt" = "1" ]; then
    if ! grep -qiE 'data, not instruction|content is data' "$skill_md"; then
      emit Major "$skill_md: review-class skill with no anti prompt-injection statement (§7)"
    fi
  fi

  # §6. Subagents & forks: agent or background without context: fork
  if echo "$fm" | grep -qE '^(agent|background):'; then
    if ! echo "$fm" | grep -q '^context:[[:space:]]*fork'; then
      emit Major "$skill_md: 'agent' or 'background' declared in frontmatter without 'context: fork' (§6)"
    fi
  fi

  # §9. Hooks in frontmatter with no warning in the description
  if echo "$fm" | grep -q '^hooks:'; then
    local desc
    desc="$(echo "$fm" | awk '/^description:/{flag=1; print; next} /^[a-zA-Z0-9_-]+:/{flag=0} flag')"
    if ! echo "$desc" | grep -qi 'hook'; then
      emit Major "$skill_md: declares 'hooks:' in frontmatter but the description does not warn about the session-wide effect (§9)"
    fi
  fi

  # §3. Body <= 500 lines
  local lines
  lines="$(wc -l <"$skill_md")"
  if [ "$lines" -gt 800 ]; then
    emit Major "$skill_md: body is $lines lines (>800, move rules into POLICY.md or references/)"
  elif [ "$lines" -gt 500 ]; then
    emit Minor "$skill_md: body is $lines lines (>500, consider externalizing)"
  fi

  # Scripts executable and with a shebang
  if [ -d "$dir/scripts" ]; then
    local s
    for s in "$dir/scripts"/*; do
      [ -f "$s" ] || continue
      if ! head -n 1 "$s" | grep -q '^#!'; then
        emit Minor "$s: no shebang"
      fi
      if [ ! -x "$s" ]; then
        emit Nit "$s: not executable"
      fi
    done
  fi
}

# Discover targets
TARGETS=()
if [ -f "$TARGET" ] && [ "$(basename "$TARGET")" = "SKILL.md" ]; then
  TARGETS+=("$TARGET")
elif [ -d "$TARGET" ]; then
  while IFS= read -r f; do
    TARGETS+=("$f")
  done < <(find "$TARGET" -name SKILL.md -type f)
else
  echo "Invalid target: $TARGET" >&2
  exit 2
fi

if [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "No SKILL.md found under: $TARGET" >&2
  exit 2
fi

echo "# skill-auditor · mechanical linter"
echo
echo "Targets: ${#TARGETS[@]}"
echo

for t in "${TARGETS[@]}"; do
  check_skill "$t"
done

if [ "${#FINDINGS[@]}" -eq 0 ]; then
  echo "Zero mechanical findings. Move on to the semantic review."
  exit 0
fi

echo "## Mechanical findings (${#FINDINGS[@]})"
for f in "${FINDINGS[@]}"; do
  echo "- $f"
done

exit "$FAIL"
