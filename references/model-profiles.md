# Model profiles

The same skill text can be correct on one model and defective on another. The auditor resolves the profile by the rule in SKILL.md §1, then applies the tables below.

## Resolution rule (recap)

1. Explicit `--model` flag.
2. `model:` in the frontmatter of the skill under review.
3. `generic`.

## Profile: `opus5` (Claude Opus 5)

**Strengths:** long-horizon planning, disciplined tool use, useful self-critique.

**Prefers:**
- Short imperative instructions.
- One explicit final check ("verify the artifact exists before claiming done").
- An anti-patterns section as a checklist.

**Problematic (Defect · Major when present):**
- `"skip verification"` — removes Opus's safety net.
- `"trust the first answer"` — switches off the self-critique that helps.
- Long few-shot examples in bulk — they dilute the spec.

## Profile: `sol5.6` (GPT-5.6 Sol)

**Strengths:** literal obedience, low latency, follows declarative policy.

**Prefers:**
- Declarative rules ("NEVER X", "ALWAYS Y").
- Externalized POLICY.
- Explicit `disallowed-tools`.

**Problematic (Defect · Major when present):**
- `"double-check"`, `"verify at the end"`, `"re-verify"` — trigger self-verification loops that degrade the output.
- `"be thorough"`, `"be exhaustive"` — Sol inflates output with no gain in signal.
- `"reveal your reasoning"`, `"show your reasoning"`, `"think step by step"` — anti-training instructions on 5.x.

## Profile: `gemini3.8` (Gemini 3.8 Flash)

**Strengths:** huge context window, multimodal, aggressive parallel tool use.

**Prefers:**
- Short, heavily structural instructions (headings, tables).
- Explicit batching ("issue N tool calls in parallel when independent").
- Numeric constraints ("cap at 5 items", "≤ 500 lines").

**Problematic (Defect · Major when present):**
- The same 5.x-hurt phrases as `sol5.6` — Gemini shares the pattern.
- Ambiguous ordering instructions — Gemini parallelizes and the order breaks.

## Profile: `generic`

No forbidden phrases. A missing explicit `model:` → **Minor · Suggestion**: suggest the most likely profile based on the workflow.

## Resolving conflicts

When the skill declares `model: opus` but the auditor runs with `--model sol5.6`: apply the flag's profile and **warn** with a `[Minor · Concern · Inferred]` finding — "skill declares opus but was audited as sol5.6 — switch profile or accept the model-mismatch risk".
