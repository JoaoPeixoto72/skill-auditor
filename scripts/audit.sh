#!/usr/bin/env bash
# skill-auditor · linter mecânico
# Read-only. Emite findings deterministicos com Confidence: Observed.
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
    emit Blocker "$skill_md: sem frontmatter YAML na linha 1"
    return
  fi

  # Extract frontmatter
  local fm
  fm="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$skill_md")"

  # name matches folder
  local name
  name="$(echo "$fm" | awk -F': *' '/^name:/{print $2; exit}')"
  if [ -z "$name" ]; then
    emit Blocker "$skill_md: frontmatter sem campo 'name'"
  elif [ "$name" != "$folder" ]; then
    emit Major "$skill_md: name='$name' não bate com folder='$folder'"
  fi

  # description present
  if ! echo "$fm" | grep -q '^description:'; then
    emit Blocker "$skill_md: frontmatter sem 'description'"
  fi

  # allowed-tools present (pode ser vazio, mas o campo tem de existir)
  if ! echo "$fm" | grep -q '^allowed-tools:'; then
    emit Minor "$skill_md: sem 'allowed-tools' declarado"
  fi

  # §4. Resources referenciados existem
  local refs
  refs="$(grep -oE '(references|scripts)/[A-Za-z0-9_.-]+' "$skill_md" | sort -u || true)"
  local ref
  for ref in $refs; do
    if [ ! -e "$dir/$ref" ]; then
      emit Blocker "$skill_md: refere '$ref' mas ficheiro não existe em $dir/"
    fi
  done

  # §5. Scripts fora da pasta
  if grep -qE 'bash +\.\./|bash +/' "$skill_md"; then
    emit Major "$skill_md: invoca script fora da pasta da skill (path absoluto ou ../)"
  fi

  # §7. Anti-injection statement em skill de review
  if echo "$name" | grep -qiE 'audit|review|lint|summariz'; then
    if ! grep -qiE 'data, not instruction|não.*instrução|content is data' "$skill_md"; then
      emit Major "$skill_md: skill de review sem statement anti prompt-injection"
    fi
  fi

  # §6. Subagentes & Forks: agent ou background sem context: fork
  if echo "$fm" | grep -qE '^(agent|background):'; then
    if ! echo "$fm" | grep -q '^context:[[:space:]]*fork'; then
      emit Major "$skill_md: 'agent' ou 'background' declarados no frontmatter sem 'context: fork' (§6)"
    fi
  fi

  # §9. Hooks: hooks no frontmatter sem aviso na description
  if echo "$fm" | grep -q '^hooks:'; then
    local desc
    desc="$(echo "$fm" | awk '/^description:/{flag=1; print; next} /^[a-zA-Z0-9_-]+:/{flag=0} flag')"
    if ! echo "$desc" | grep -qi 'hook'; then
      emit Major "$skill_md: declara 'hooks:' no frontmatter mas a description não avisa sobre o efeito na sessão (§9)"
    fi
  fi

  # §3. Body ≤ 500 linhas
  local lines
  lines="$(wc -l <"$skill_md")"
  if [ "$lines" -gt 800 ]; then
    emit Major "$skill_md: body com $lines linhas (>800, mover regras para POLICY.md ou references/)"
  elif [ "$lines" -gt 500 ]; then
    emit Minor "$skill_md: body com $lines linhas (>500, considerar externalizar)"
  fi

  # Scripts executáveis com shebang
  if [ -d "$dir/scripts" ]; then
    local s
    for s in "$dir/scripts"/*; do
      [ -f "$s" ] || continue
      if ! head -n 1 "$s" | grep -q '^#!'; then
        emit Minor "$s: sem shebang"
      fi
      if [ ! -x "$s" ]; then
        emit Nit "$s: sem permissão de execução"
      fi
    done
  fi
}

# Descobrir alvos
TARGETS=()
if [ -f "$TARGET" ] && [ "$(basename "$TARGET")" = "SKILL.md" ]; then
  TARGETS+=("$TARGET")
elif [ -d "$TARGET" ]; then
  while IFS= read -r f; do
    TARGETS+=("$f")
  done < <(find "$TARGET" -name SKILL.md -type f)
else
  echo "Alvo inválido: $TARGET" >&2
  exit 2
fi

if [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "Nenhum SKILL.md encontrado em: $TARGET" >&2
  exit 2
fi

echo "# skill-auditor · linter mecânico"
echo
echo "Alvos: ${#TARGETS[@]}"
echo

for t in "${TARGETS[@]}"; do
  check_skill "$t"
done

if [ "${#FINDINGS[@]}" -eq 0 ]; then
  echo "Zero findings mecânicos. Passar para revisão semântica."
  exit 0
fi

echo "## Findings mecânicos (${#FINDINGS[@]})"
for f in "${FINDINGS[@]}"; do
  echo "- $f"
done

exit "$FAIL"
