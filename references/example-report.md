# Audit: ux-forms

**Verdict:** Reject
**Depth:** deep
**Model profile:** sol5.6 (resolved from --model)
**Reviewed:** design-skills-v3.1/core/ux-forms/SKILL.md

## Summary

A well-structured skill that does not run: step 4 calls a script that is not in the folder (Blocker, and the reason the verdict is `Reject` rather than `Needs revision` — highest severity wins). Two Majors behind it: a 5.x-hurt phrase in the workflow, and a missing `disallowed-tools` on a skill that only reads. Note what the ordering shows — the Blocker came from the Claims pass, after all eight structural dimensions had passed.

## Findings

| # | Severity | Type | Confidence | Title | Location |
|---|----------|------|------------|-------|----------|
| 1 | Major | Defect | Observed | "double-check" phrase incompatible with the sol5.6 profile | SKILL.md:34 |
| 2 | Major | Defect | Observed | Missing `disallowed-tools` on a read-only skill | SKILL.md:1-8 |
| 3 | Minor | Concern | Observed | Description does not say when NOT to use it | SKILL.md:3 |
| 4 | Minor | Suggestion | Inferred | Body close to the ceiling (487 lines) | SKILL.md:1-487 |
| 5 | Nit | Suggestion | Observed | Inconsistent bullets ("- " vs "* ") | SKILL.md:120-140 |
| 6 | Blocker | Defect | Observed | Step 4 runs a script that does not exist | SKILL.md:88 |

### Detail

**[Major · Defect · Observed] "double-check" phrase incompatible with the sol5.6 profile**
- Evidence: `SKILL.md:34` — "Before returning, double-check that every field has a label."
- Impact: on `sol5.6` this triggers a self-verification loop that degrades latency and signal.
- Fix: replace with "Every field must have a label. If any lacks one, list it in findings."

**[Major · Defect · Observed] Missing `disallowed-tools` on a read-only skill**
- Evidence: `SKILL.md:1-8` — frontmatter carries only `allowed-tools: Read, Grep`.
- Impact: the skill can be invoked in a context with implicit `Edit` and write to the file under review.
- Fix: add `disallowed-tools: Edit, Write, MultiEdit, NotebookEdit`.

**[Minor · Concern · Observed] Description does not say when NOT to use it**
- Evidence: `SKILL.md:3` — "Audits UX form patterns."
- Impact: overlaps `ux-general` with no disambiguation criterion.
- Fix: add "Do not use for landing pages or marketing — use ux-visual-design."

**[Minor · Suggestion · Inferred] Body close to the ceiling (487 lines)**
- Evidence: `wc -l SKILL.md` = 487.
- Impact: another 14 lines crosses the operational threshold.
- Fix: move the long checklist under "Common patterns" into `references/patterns.md`.

**[Nit · Suggestion · Observed] Inconsistent bullets**
- Evidence: `SKILL.md:120-140` — mixes `- ` and `* `.
- Fix: normalize to `- `.

**[Blocker · Defect · Observed] Step 4 runs a script that does not exist**
- Evidence: `SKILL.md:88` — "run `node scripts/contrast.mjs` and paste the ratio"; `node scripts/contrast.mjs --help` exits 127, and `scripts/` holds only `audit.sh`.
- Impact: the workflow's contrast check never runs. Every structural dimension passed — this was only reachable by running the command (POLICY §10).
- Fix: ship the script, or drop the step and compute the ratio inline.

## Claims (POLICY §10)

| Claim | Command run | State |
|---|---|---|
| "the 12 form patterns in `references/patterns.md`" | `grep -c '^### ' references/patterns.md` → 12 | CONFIRMED |
| "runs on Node 18+" | `node -v` → v22.4.0 (18+ not disproved, older not tested) | UNVERIFIED |
| "`scripts/contrast.mjs` prints the WCAG ratio" | `node scripts/contrast.mjs --help` → exit 127, no such file | REFUTED → Finding #6 |

Three claims, one refuted. The refuted one is the finding no amount of reading
the skill would have produced: the workflow's step 4 runs a script that is not
there, and every structural dimension passed.

## Top fixes (ordered)

1. Swap "double-check" for an affirmative statement (§Major #1).
2. Add `disallowed-tools` (§Major #2).
3. Refine the description with a "do not use when" clause (§Minor #3).
4. Move the "Common patterns" section into `references/` (§Minor #4).

## Trigger tests (proposed, not executed)

1. "audit this login form for accessibility and validation" → should activate
2. "check our checkout multi-step form UX" → should activate
3. "review this landing page visual layout" → should **NOT** activate (hand off to `ux-visual-design`)

## Meta

- Linter: fail — 1 mechanical finding (#6, the missing script; §4 resolves against the skill folder and the repo root before reporting).
- Semantic passes: spec, coverage, triggering, resources, instructions, context, permissions, portability, security, model fit, claims.
- Skipped: none. 3 claims extracted, 1 refuted — Claims table above.
