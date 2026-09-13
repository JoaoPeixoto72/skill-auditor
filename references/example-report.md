# Audit: ux-forms

**Verdict:** Needs revision
**Depth:** standard
**Model profile:** sol5.6 (resolved from --model)
**Reviewed:** design-skills-v3/core/ux-forms/SKILL.md

## Summary

Skill funcional e bem estruturada. Dois Majors bloqueiam release: uma phrase 5.x-hurt no workflow e ausência de `disallowed-tools` numa skill que só lê. Três Minors de wording.

## Findings

| # | Severity | Type | Confidence | Title | Location |
|---|----------|------|------------|-------|----------|
| 1 | Major | Defect | Observed | "double-check" phrase incompatível com profile sol5.6 | SKILL.md:34 |
| 2 | Major | Defect | Observed | Falta `disallowed-tools` em skill read-only | SKILL.md:1-8 |
| 3 | Minor | Concern | Observed | Description não diz quando NÃO usar | SKILL.md:3 |
| 4 | Minor | Suggestion | Inferred | Body próximo do teto (487 linhas) | SKILL.md:1-487 |
| 5 | Nit | Suggestion | Observed | Inconsistência em bullets ("- " vs "* ") | SKILL.md:120-140 |

### Detail

**[Major · Defect · Observed] "double-check" phrase incompatível com profile sol5.6**
- Evidence: `SKILL.md:34` — "Before returning, double-check that every field has a label."
- Impact: no `sol5.6`, dispara loop de auto-verificação que degrada latency e sinal.
- Fix: substituir por "Every field must have a label. If any lacks one, list it in findings."

**[Major · Defect · Observed] Falta `disallowed-tools` em skill read-only**
- Evidence: `SKILL.md:1-8` — frontmatter só tem `allowed-tools: Read, Grep`.
- Impact: skill pode ser invocada num contexto com `Edit` implícito e escrever no ficheiro sob review.
- Fix: adicionar `disallowed-tools: Edit, Write, MultiEdit, NotebookEdit`.

**[Minor · Concern · Observed] Description não diz quando NÃO usar**
- Evidence: `SKILL.md:3` — "Audits UX form patterns."
- Impact: sobrepõe-se a `ux-general` sem critério de disambiguação.
- Fix: adicionar "Não usar para landing pages ou marketing — usar ux-visual-design."

**[Minor · Suggestion · Inferred] Body próximo do teto (487 linhas)**
- Evidence: `wc -l SKILL.md` = 487.
- Impact: crescer +14 linhas cruza o threshold operacional.
- Fix: mover a checklist longa da secção "Common patterns" para `references/patterns.md`.

**[Nit · Suggestion · Observed] Inconsistência em bullets**
- Evidence: `SKILL.md:120-140` — mistura `- ` e `* `.
- Fix: normalizar para `- `.

## Top fixes (ordered)

1. Trocar "double-check" por afirmativa (§Major #1).
2. Adicionar `disallowed-tools` (§Major #2).
3. Refinar description com "não usar quando" (§Minor #3).
4. Mover secção "Common patterns" para `references/` (§Minor #4).

## Trigger tests (proposed, not executed)

1. "audit this login form for accessibility and validation" → deve ativar
2. "check our checkout multi-step form UX" → deve ativar
3. "review this landing page visual layout" → **NÃO** deve ativar (repassar a `ux-visual-design`)

## Meta

- Linter: pass — 0 mechanical findings.
- Semantic passes: spec, coverage, triggering, resources, instructions, context, permissions, portability.
- Skipped: security, model fit (não pedido em `--depth standard` — model fit foi checado ad-hoc para Finding #1).

