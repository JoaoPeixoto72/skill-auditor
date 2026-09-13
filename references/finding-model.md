# Finding model

## Type

- **Defect** — violates an explicit rule in `POLICY.md`. Not subjective.
- **Concern** — a real risk POLICY does not cover. Requires judgment.
- **Suggestion** — a quality improvement that does not block release.

## Severity

- **Blocker** — stops the skill from working, or introduces a security risk. Verdict → `Reject`.
- **Major** — degrades quality / triggering / correctness. Verdict ≥ `Needs revision`.
- **Minor** — a real problem, but workable around. Verdict may stay `Approve with nits`.
- **Nit** — style, wording, formatting.

## Confidence

- **Observed** — found directly in the file; the evidence cites a line and a literal excerpt.
- **Inferred** — deduced from circumstantial evidence (a dependency on a missing file, likely behaviour).
- **Unknown** — not verifiable within the review's scope; recorded for the reader to decide.

**Reader's rule:**
- `Observed` → apply the fix, no further discussion.
- `Inferred` → confirm with the author before applying.
- `Unknown` → treat as a discovery TODO, not an action.

## Verdict enum

Precedence (highest severity wins, not the count):

| Verdict | Condition |
|---|---|
| `Reject` | ≥1 Blocker |
| `Needs revision` | 0 Blockers, ≥1 Major |
| `Approve with nits` | 0 Blockers, 0 Majors, ≥1 Minor |
| `Ready with suggestions` | Suggestions only |
| `Ready` | Zero findings |

## Anti-patterns in findings

- A finding with no literal evidence → collapses to Confidence `Unknown` and is not actionable.
- Merging Defect and Concern → the policy becomes invisible.
- Multiple findings for the same problem → fold them into one with sub-bullets.
- Inflated severity ("Blocker" for wording) → the operator stops trusting the auditor.
