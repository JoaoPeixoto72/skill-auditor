#!/usr/bin/env bash
# skill-auditor · mechanical linter
# Read-only. Emits deterministic findings with Confidence: Observed.
# Usage: bash scripts/audit.sh <skill-path-or-repo>
#
# Everything in here is decidable by a command. What needs judgment is not in
# here — it is the semantic review in SKILL.md §4. The rule this file exists to
# hold: a check that SKILL.md promises and this script does not implement is
# worse than no check, because the operator reads "linter: pass" and believes it
# ran (that was true of the absolute-path check until 2026-09-13).

set -euo pipefail

TARGET="${1:-.}"
FAIL=0
FINDINGS=()

emit() {
  local sev="$1" ; shift
  FINDINGS+=("[${sev}] $*")
  case "$sev" in
    Blocker|Major) FAIL=1 ;;
  esac
}

# A skill folder may sit inside a repository whose root owns scripts the skill
# legitimately names. Without this, `scripts/x.mjs` at the repo root reads as a
# missing resource and a healthy skill gets a Blocker (§4).
repo_root_for() {
  local d="$1"
  while [ "$d" != "/" ] && [ -n "$d" ]; do
    if [ -e "$d/.git" ] && [ "$d" != "$2" ]; then
      echo "$d"
      return
    fi
    d="$(dirname "$d")"
  done
  echo ""
}

# Extract the `description:` value, block scalar or single line.
description_of() {
  awk '/^description:/{f=1} f&&/^[a-zA-Z0-9_-]+:/&&!/^description:/{exit} f{print}' <<<"$1"
}

check_skill() {
  local skill_md="$1"
  local dir folder fm name lines
  dir="$(cd "$(dirname "$skill_md")" && pwd)"
  folder="$(basename "$dir")"
  local root
  root="$(repo_root_for "$(dirname "$dir")" "$dir")"

  # §1. Frontmatter
  if ! head -n 1 "$skill_md" | grep -q '^---$'; then
    emit Blocker "$skill_md: no YAML frontmatter on line 1"
    return
  fi
  fm="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$skill_md")"
  lines="$(wc -l <"$skill_md")"

  name="$(awk -F': *' '/^name:/{print $2; exit}' <<<"$fm")"
  if [ -z "$name" ]; then
    emit Blocker "$skill_md: frontmatter has no 'name' field"
  elif [ "$name" != "$folder" ]; then
    emit Major "$skill_md: name='$name' does not match folder='$folder'"
  fi

  grep -q '^description:' <<<"$fm" || emit Blocker "$skill_md: frontmatter has no 'description'"

  # §1. Minimal frontmatter is a Major, not a missing-field Minor. Only the
  # trivial-glue exception (under 20 lines) escapes it.
  local keys
  keys="$(grep -cE '^[a-zA-Z0-9_-]+:' <<<"$fm" || true)"
  if [ "$keys" -le 2 ] && [ "$lines" -gt 20 ]; then
    emit Major "$skill_md: minimal frontmatter (name + description only) on a $lines-line skill (§1)"
  elif ! grep -q '^allowed-tools:' <<<"$fm"; then
    emit Minor "$skill_md: no 'allowed-tools' declared (§1)"
  fi

  # §1. `model:` must be a model id the harness resolves — not a profile name.
  local modelo esforco
  modelo="$(awk -F': *' '/^model:/{print $2; exit}' <<<"$fm" | tr -d '\r')"
  if [ -n "$modelo" ]; then
    case "$modelo" in
      opus|sonnet|haiku|inherit) ;;
      *) emit Major "$skill_md: model='$modelo' is not a resolvable model id (§1: opus|sonnet|haiku|inherit; the auditor profile is derived from it, never written into it)" ;;
    esac
  fi
  esforco="$(awk -F': *' '/^effort:/{print $2; exit}' <<<"$fm" | tr -d '\r')"
  if [ -n "$esforco" ]; then
    case "$esforco" in
      low|medium|high) ;;
      *) emit Minor "$skill_md: effort='$esforco' is not one of low|medium|high (§1)" ;;
    esac
  fi

  # §4. Referenced resources exist — in the skill folder, or at the repo root.
  # Glob patterns are stripped first: `ls assets/components/*.tsx` is a command
  # in an example, not a declared resource, and the extractor would otherwise
  # capture the `assets/components/` head of it and demand it exist here. That
  # false Blocker appeared the moment this skill documented a Claims example —
  # §4 is the check most likely to accuse a healthy skill, so it strips before
  # it reads.
  local refs ref
  # The *whole* path is captured, not the `scripts/...` tail: a skill that names
  # a sibling skill's script (`.claude/skills/other/scripts/x.ps1`) was reported
  # as missing because only the tail was looked up. It resolves — one directory
  # up — and the honest finding there is the Minor below, not a Blocker.
  refs="$(sed -E 's#[A-Za-z0-9_./-]*/[A-Za-z0-9_./*-]*\*[A-Za-z0-9_./*-]*##g' "$skill_md" \
    | grep -oE '[A-Za-z0-9_./-]*(references|scripts|assets|baselines|templates)/[A-Za-z0-9_./-]+' \
    | sed 's/[.]$//' | sort -u || true)"
  for ref in $refs; do
    if [ -e "$dir/$ref" ]; then
      continue
    elif [ -n "$root" ] && [ -e "$root/$ref" ]; then
      # A skill naming its own script by the path from the repo root
      # (`.claude/skills/<self>/scripts/x.py`) is not depending on anything
      # outside itself — it is the same file, written the long way.
      case "$root/$ref" in
        "$dir"/*) continue ;;
      esac
      emit Minor "$skill_md: '$ref' lives outside the skill folder — works here, breaks on a global install unless what holds it is installed too (§4/§5)"
    else
      emit Blocker "$skill_md: references '$ref' but it exists neither in $dir/ nor at the repo root"
    fi
  done

  # §5. Scripts invoked from outside the skill folder
  if grep -qE 'bash +\.\./|bash +/' "$skill_md"; then
    emit Major "$skill_md: invokes a script outside the skill folder (absolute path or ../) (§5)"
  fi

  # §6. A Bash permission pattern has to match the command as written: a rule
  # for `scripts/x.sh` never authorizes `bash scripts/x.sh`.
  local padroes p cmd
  padroes="$(grep -oE 'Bash\([^)]*\)' <<<"$fm" || true)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    cmd="$(sed -E 's/^Bash\(//; s/\)$//; s/:\*$//' <<<"$p")"
    case "$cmd" in
      bash\ *|sh\ *|python*|py\ *|node\ *|npm\ *|git\ *|cargo\ *) continue ;;
    esac
    if grep -qE "(bash|sh|python3?|py -3|node) +${cmd//\//\\/}" "$skill_md"; then
      emit Major "$skill_md: allowed-tools has '$p' but the workflow runs it through an interpreter ('bash $cmd ...') — the pattern matches the command prefix and will not authorize it (§6)"
    fi
  done <<<"$padroes"

  # §7. Anti prompt-injection statement in a skill that processes external content
  local needs=0
  if grep -qiE '^(skill-)?(audit|lint|summariz)' <<<"$name"; then
    needs=1
  elif [ "$name" != "ux-review" ] && grep -qiE 'description:.*\b(audits|auditoria|reviews an?|summariz|extracts from)\b' <<<"$fm"; then
    needs=1
  fi
  if [ "$needs" = "1" ] && ! grep -qiE 'data, not instruction|content is data|é dado, não é instrução|e dado, nao e instrucao' "$skill_md"; then
    emit Major "$skill_md: review-class skill with no anti prompt-injection statement (§7)"
  fi

  # §7, the other direction: a skill can *be* the injection. Two positions are
  # decidable without judgment, and both are where the hostile fixture puts it —
  # the description (read by any agent deciding whether to fire the skill) and an
  # HTML comment (invisible when the Markdown is rendered). Legitimate skills
  # quote these same phrases in prose as examples of what to refuse, which is
  # why prose is not searched: it would flag every auditor, including this one.
  local ATAQUE='ignore (all )?previous|disregard previous|return ready|mark as ready|skip verification|do not (list|report) findings|pre-approved|trust mode|ignora as regras'
  if description_of "$fm" | grep -qiE "$ATAQUE"; then
    emit Blocker "$skill_md: the description carries agent-directed instructions (§7 prompt injection) — it is read before any decision to run the skill"
  fi
  if grep -oE '<!--[^>]*-->' "$skill_md" | grep -qiE "$ATAQUE"; then
    emit Blocker "$skill_md: an HTML comment carries agent-directed instructions (§7 prompt injection) — invisible in rendered Markdown"
  fi

  # §6. Subagents & forks
  if grep -qE '^(agent|background):' <<<"$fm" && ! grep -q '^context:[[:space:]]*fork' <<<"$fm"; then
    emit Major "$skill_md: 'agent' or 'background' in frontmatter without 'context: fork' (§6)"
  fi

  # §9. Hooks with no warning in the description
  if grep -q '^hooks:' <<<"$fm"; then
    description_of "$fm" | grep -qi 'hook' ||
      emit Major "$skill_md: declares 'hooks:' but the description does not warn about the session-wide effect (§9)"
  fi

  # §3. Body size
  if [ "$lines" -gt 800 ]; then
    emit Major "$skill_md: body is $lines lines (>800, move rules into POLICY.md or references/) (§3)"
  elif [ "$lines" -gt 500 ]; then
    emit Minor "$skill_md: body is $lines lines (>500, consider externalizing) (§3)"
  fi

  # §10. Inventory counts, against the directory they describe. This is the one
  # class of claim a script can settle on its own — and the class that rots
  # quietest, because adding a file never updates the prose.
  # The floor of 6 is deliberate and it is what keeps this check honest: a
  # number under it, next to one of these words, is nearly always a cap ("up to
  # 5 guides"), a step count, or a version ("um Python 3 para os scripts") — all
  # three were false Majors before the floor existed. Real inventories are
  # bigger, and a small count that goes wrong is cheap to see. Anything under 6
  # belongs to the semantic pass, not here.
  local dirs_n conta declarado alvo palavra
  while IFS= read -r linha; do
    [ -n "$linha" ] || continue
    declarado="$(grep -oE '^[0-9]+' <<<"$linha")"
    [ "$declarado" -ge 6 ] || continue
    palavra="$(tr 'A-Z' 'a-z' <<<"$linha")"
    case "$palavra" in
      *"up to"*|*"at most"*|*cap*|*at[eé]*|*"no m[aá]ximo"*|*"batches of"*) continue ;;
    esac
    alvo=""
    case "$palavra" in
      *componente*|*component*) alvo="assets/components:*.tsx" ;;
      *guia*|*guide*|*referenc*|*referê*) alvo="references:*.md" ;;
      *script*) alvo="scripts:*" ;;
    esac
    [ -n "$alvo" ] || continue
    dirs_n="${alvo%%:*}"
    [ -d "$dir/$dirs_n" ] || continue
    conta="$(find "$dir/$dirs_n" -maxdepth 1 -type f -name "${alvo##*:}" | wc -l | tr -d ' ')"
    if [ "$declarado" != "$conta" ]; then
      emit Major "$skill_md: claims $declarado in '$dirs_n' but the folder holds $conta (§10 REFUTED — 'find $dirs_n -maxdepth 1 -name ${alvo##*:} | wc -l')"
    fi
  done <<<"$(grep -ohE '[0-9]{1,3}( +[A-Za-zÀ-ÿ._-]+){0,3} +[A-Za-zÀ-ÿ._-]*([Cc]omponente|[Cc]omponent|[Gg]uia|[Gg]uide|[Rr]eferenc|[Rr]eferê|[Ss]cript)[A-Za-zÀ-ÿ]*' "$skill_md" || true)"

  # §10. Absolute paths. Promised by SKILL.md since the first version and never
  # implemented until now — which is why a skill full of C:\Users\... passed.
  local absolutos
  absolutos="$(grep -ohE '([A-Za-z]:\\[A-Za-z0-9_\\.-]+|/(home|Users|mnt)/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]*)' "$skill_md" | sort -u | head -3 || true)"
  if [ -n "$absolutos" ]; then
    if grep -qiE 'desta m[aá]quina|machine-specific|paths here are local' "$skill_md"; then
      emit Nit "$skill_md: carries absolute paths ($(tr '\n' ' ' <<<"$absolutos")) — declared as machine-specific, so this is a note, not a defect"
    else
      emit Minor "$skill_md: hardcoded absolute paths ($(tr '\n' ' ' <<<"$absolutos")) with no declaration that they are machine-specific (§10)"
    fi
  fi

  # §11. A skill named in the description as the alternative must be installed.
  # Two forms, because the one that actually broke was the unquoted one: "— use
  # production-audit." carried no backticks and sailed through a backtick-only
  # rule. Bare kebab words are not searched everywhere (English compounds like
  # "deep-dive" or "domain-specific" would flood it) — only right after a
  # routing verb, which is where a handoff is written.
  local aponta tok
  aponta="$( { description_of "$fm" | grep -oE '`[a-z0-9]+(-[a-z0-9]+)+`' | tr -d '`'
              description_of "$fm" | grep -oiE '\b(use|usar)[[:space:]]+[a-z0-9]+(-[a-z0-9]+)+' \
                | tr 'A-Z' 'a-z' | sed -E 's/^(use|usar)[[:space:]]+//'; } | sort -u || true)"
  for tok in $aponta; do
    [ "$tok" = "$name" ] && continue
    if [ ! -d "$dir/../$tok" ]; then
      emit Major "$skill_md: description routes to \`$tok\`, which is not installed beside it — the discriminating half of the trigger points at nothing (§11)"
    fi
  done

  # Scripts executable and with a shebang — only the ones a POSIX shell can run
  # directly. A `.ps1` or a `.bat` is Windows-only, is invoked through its own
  # interpreter, and a shebang in one would be wrong: demanding it there is the
  # linter inventing a defect.
  if [ -d "$dir/scripts" ]; then
    local s
    for s in "$dir/scripts"/*; do
      [ -f "$s" ] || continue
      case "$s" in
        *.ps1|*.psm1|*.bat|*.cmd|*.mjs|*.js|*.ts|*.json|*.md) continue ;;
      esac
      head -n 1 "$s" | grep -q '^#!' || emit Minor "$s: no shebang"
      [ -x "$s" ] || emit Nit "$s: not executable"
    done
  fi
}

# Discover targets. Fixtures are deliberately malformed skills that live inside
# an auditor; enumerating them reports an author's test material as their
# defects — and the hostile fixture is built to look like a real skill.
TARGETS=()
if [ -f "$TARGET" ] && [ "$(basename "$TARGET")" = "SKILL.md" ]; then
  TARGETS+=("$TARGET")
elif [ -d "$TARGET" ]; then
  while IFS= read -r f; do
    case "$f" in
      */fixtures/*|*/tests/*|*/.git/*) continue ;;
    esac
    TARGETS+=("$f")
  done < <(find "$TARGET" -name SKILL.md -type f | sort)
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
if [ "${#TARGETS[@]}" -gt 5 ]; then
  echo
  echo "Note: ${#TARGETS[@]} skills. The linter costs nothing and did them all;"
  echo "the *semantic* review splits into batches of 5 (SKILL.md anti-patterns)."
fi
echo

for t in "${TARGETS[@]}"; do
  check_skill "$t"
done

if [ "${#FINDINGS[@]}" -eq 0 ]; then
  echo "Zero mechanical findings. Move on to the semantic review."
  echo
  echo "Reminder: the Claims table (§10) is not mechanical. Counts, paths and"
  echo "commands were checked here; every other claim about the audited repo is"
  echo "still UNVERIFIED until a command settles it."
  exit 0
fi

echo "## Mechanical findings (${#FINDINGS[@]})"
for f in "${FINDINGS[@]}"; do
  echo "- $f"
done
echo
echo "Reminder: §10 claims beyond counts/paths/commands are still UNVERIFIED."

exit "$FAIL"
