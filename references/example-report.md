# Audit: ux-forms

**Verdict:** Needs revision
**Depth:** standard
**Model profile:** sol5.6 (resolved from --model)
**Reviewed:** design-skills-v3.1/core/ux-forms/SKILL.md

## Summary

A working, well-structured skill. Two Majors block release: a 5.x-hurt phrase in the workflow, and a missing `disallowed-tools` on a skill that only reads. Three Minors of wording.

## Findings

| # | Severity | Type | Confidence | Title | Location |
|---|----------|------|------------|-------|----------|
| 1 | Major | Defect | Observed | "double-check" phrase incompatible with the sol5.6 profile | SKILL.md:34 |
| 2 | Major | Defect | Observed | Missing `disallowed-tools` on a read-only skill | SKILL.md:1-8 |
| 3 | Minor | Concern | Observed | Description does not say when NOT to use it | SKILL.md:3 |
| 4 | Minor | Suggestion | Inferred | Body close to the ceiling (487 lines) | SKILL.md:1-487 |
| 5 | Nit | Suggestion | Observed | Inconsistent bullets ("- " vs "* ") | SKILL.md:120-140 |

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

- Linter: pass — 0 mechanical findings.
- Semantic passes: spec, coverage, triggering, resources, instructions, context, permissions, portability.
- Skipped: security, model fit (not requested at `--depth standard` — model fit was checked ad hoc for Finding #1).
