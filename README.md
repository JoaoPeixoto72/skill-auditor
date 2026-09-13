# skill-auditor v4.1 (híbrida · state of the art)

Agent Skill para auditar outras Agent Skills. Combina:

- **Revisão semântica** — model-aware, com policy externalizada, suíte de Trigger Tests e finding model rico. Inspirada em `JoaoPeixoto72/Skill-Reviewer`.
- **Linter mecânico** — `scripts/audit.sh`, determinístico, ~ms, apanha regressões estruturais sem gastar tokens.

## Estrutura

```
skill-auditor/
├── SKILL.md                       # entry point (thin)
├── POLICY.md                      # regras autoritativas (§1–§9)
├── scripts/
│   └── audit.sh                   # linter mecânico (frontmatter, hooks, refs, limits)
└── references/
    ├── model-profiles.md          # opus5 / sol5.6 / gemini3.8 / generic
    ├── finding-model.md           # Type / Severity / Confidence / Verdict
    ├── example-report.md          # formato canónico do output + Trigger Tests
    ├── anti-injection.md          # statement + heurísticas
    └── fixtures/
        └── hostile-skill/         # fixture para testar detecção
```

## Instalar

### Claude Code
```bash
cp -r skill-auditor ~/.claude/skills/
```

### Google Antigravity
```bash
cp -r skill-auditor ~/.gemini/config/skills/
```

### Codex CLI
```bash
cp -r skill-auditor ~/.codex/skills/
```

## Invocar

```
/skill-auditor <path> [--depth quick|standard|deep] [--model opus5|sol5.6|gemini3.8|generic]
```

Exemplos:
- `/skill-auditor design-skills-v3/core/ux-forms` — standard, model resolvido do frontmatter.
- `/skill-auditor ./skills --target repo --depth quick` — sweep rápido do repo.
- `/skill-auditor ./my-skill --depth deep --model sol5.6` — review completo com model forçado.

## Correr só o linter (CI hook)

```bash
bash skill-auditor/scripts/audit.sh <path>
```

Exit codes:
- `0` — zero findings ou só Minor/Nit
- `1` — ≥1 Major ou Blocker
- `2` — alvo inválido

## Verdict enum

`Reject` · `Needs revision` · `Approve with nits` · `Ready with suggestions` · `Ready`

Regra: maior severity manda, não contagem. Detalhe em `references/finding-model.md`.

## Novidades v4.1 (Elevação)

- **Suíte de Trigger Tests (Near-Misses)**: toda correção de `description` formula obrigatoriamente testes positivos e near-misses negativos (POLICY §2).
- **Auditoria de Session Blast Radius & Hooks**: detecção mecânica e semântica de `hooks:` de sessão não documentados na description (POLICY §9).
- **Consistência de Subagentes Forked**: alerta para `agent`/`background` isolados sem `context: fork` (POLICY §6).
- **Model Profiles atualizados**: perfil para `gemini3.8` (Antigravity), `sol5.6` e `opus5`.
- **Anti prompt-injection testado**: statement explícito e fixture hostil em `references/fixtures/`.

## Créditos

Design inspirado em [`JoaoPeixoto72/Skill-Reviewer`](https://github.com/JoaoPeixoto72/Skill-Reviewer). Camada mecânica original de `design-skills-v3`.

