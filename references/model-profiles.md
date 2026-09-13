# Model Profiles

O mesmo texto de skill pode ser correcto num modelo e defectuoso noutro. O auditor resolve o profile pela regra em SKILL.md §1, e aplica as tabelas abaixo.

## Regra de resolução (recap)

1. Flag `--model` explícita.
2. `model:` no frontmatter da skill sob revisão.
3. `generic`.

## Profile: `opus5` (Claude Opus 5)

**Strengths:** planeamento longo, tool-use disciplinado, self-critique útil.

**Prefere:**
- Instruções imperativas curtas.
- Uma verificação final explícita ("verify the artifact exists before claiming done").
- Anti-patterns section como checklist.

**Problemático (Defect · Major se presente):**
- `"skip verification"` — Opus perde a rede de segurança.
- `"trust the first answer"` — desliga o self-critique útil.
- Excesso de exemplos few-shot longos — dilui a spec.

## Profile: `sol5.6` (GPT-5.6 Sol)

**Strengths:** obediência literal, latência baixa, seguimento de policy declarativa.

**Prefere:**
- Regras declarativas ("NEVER X", "ALWAYS Y").
- POLICY externalizada.
- `disallowed-tools` explícito.

**Problemático (Defect · Major se presente):**
- `"double-check"`, `"verify at the end"`, `"re-verify"` — dispara loops de auto-verificação que degradam output.
- `"be thorough"`, `"be exhaustive"` — o Sol infla o output sem ganho de sinal.
- `"reveal your reasoning"`, `"show your reasoning"`, `"think step by step"` — anti-training instructions no 5.x.

## Profile: `gemini3.8` (Gemini 3.8 Flash)

**Strengths:** context window vasto, multimodal, tool-use paralelo agressivo.

**Prefere:**
- Instruções curtas, muito estruturais (headings, tabelas).
- Batching explícito ("issue N tool calls in parallel when independent").
- Constraints numéricas ("cap at 5 items", "≤ 500 lines").

**Problemático (Defect · Major se presente):**
- Mesmas 5.x-hurt phrases do `sol5.6` — Gemini partilha o padrão.
- Instruções ambíguas de ordem — Gemini paraleliza e a ordem quebra-se.

## Profile: `generic`

Nenhuma phrase proibida. Ausência de `model:` explícito → **Minor · Suggestion**: sugerir o profile mais provável baseado no workflow.

## Resolver conflitos

Quando a skill declara `model: opus` mas o auditor corre com `--model sol5.6`: aplicar o profile da flag e **avisar** com finding [Minor · Concern · Inferred] "skill declara opus mas foi auditada como sol5.6 — trocar profile ou aceitar risco de model mismatch".
