# Model profiles

## Contents

1. What a profile is
2. Resolution
3. Universal principles (every profile)
4. `generic`
5. `claude`
6. Model-fit finding format
7. Adding a profile

---

## 1. What a profile is

A profile lists instruction patterns that a model family's **vendor has
published** as helping or hurting. It is readiness guidance, not security
policy, and every rule in it cites the page it comes from. A family without
such a page has no profile: it is audited as `generic`.

A model-fit finding requires an active profile, the literal phrase, its
operational effect, and a replacement. `scripts/readiness-audit.py` detects the
phrases mechanically; a phrase inside a fenced code block is an illustration
and is not reported.

## 2. Resolution

In order, the first that applies:

1. `--model <profile>`;
2. frontmatter `model:` of `opus`, `sonnet`, `haiku`, `fable`, `inherit`, or a
   `claude-…` model id → `claude`;
3. the skill lives under `.claude/`, or inside a plugin with `.claude-plugin/`
   → `claude` (source: `host: Claude Code`);
4. `generic`.

The report records the source (`--model`, `frontmatter model: opus`,
`host: Claude Code`, `fallback`). A profile name is not a harness model id:
never propose `model: claude` or `model: generic`.

## 3. Universal principles (every profile)

- **Explicit conditions** — "If a referenced path does not exist, record a
  Major finding", not "handle missing paths appropriately".
- **Bounded procedures** — "at most five skills per batch", not "as many as
  necessary".
- **Observable outcomes** — "run the parser; non-zero exit means invalid
  frontmatter", not "ensure it looks valid".
- **Rules separate from examples** — an example illustrates a rule and never
  adds one silently.
- **Failure behaviour defined** — missing command, parse failure, missing
  file, ambiguous target.
- **One authority** — no pair of rules that contradict ("never ask" / "ask
  whenever unsure"); give the order instead.

## 4. `generic`

Only the universal principles. A phrase is reported only when it creates an
unbounded loop, a contradiction, unverifiable behaviour, or no completion
condition. Family-specific preferences are not defects here.

## 5. `claude`

Sources, read 2026-09-23:

- Prompting best practices (current models) —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices
- Prompting Claude Opus 5 —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-opus-5
- Prompting Claude Sonnet 5 —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-sonnet-5
- Skill authoring best practices —
  https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

What changed from the models most skills were first written for, and what the
audit reports:

| Pattern | Why it now hurts | Severity | Replacement |
|---|---|---|---|
| `CRITICAL:`, `YOU MUST`, `MUST ALWAYS` | Current models are more responsive to the system prompt; emphasis written to fix under-triggering now over-triggers | Minor | The condition in plain words: "Use X when …" |
| "If in doubt, use X", "default to using X" | Blanket defaults cause over-triggering | Minor | Name the situations where X helps |
| "double-check", "re-verify", "verify your work", "use a subagent to verify" | Opus 5 verifies its own work unprompted; explicit re-checks cause over-verification | Minor | Remove, or a concrete gate: "Continue only when `<command>` exits 0" |
| "only report high-severity", "be conservative", "don't nitpick" | Sonnet 5 and Opus 5 follow the filter literally and drop real findings | Minor | A concrete bar: "report anything that could cause incorrect behaviour; omit pure style" |
| "do not think", "without thinking" | With thinking disabled it increases internal-tag leakage | Minor | Remove; control cost with effort |
| "after every N tool calls, summarize" | Progress scaffolding current models no longer need | Nit | Describe the update wanted |

Also from these pages, reviewed semantically (no mechanical detector):

- **Literal scope** (Sonnet 5): an instruction is not generalized from one
  item to others — state the scope ("every section, not just the first").
- **Positive examples beat prohibitions**: show the wanted output rather than
  a list of "don't".
- **Explain why**: a rule with its reason generalizes; a bare rule does not.
- **Conciseness**: the model already knows general practice; a skill adds
  only what it does not know.

The format's own rules — name ≤ 64 characters without "anthropic" or
"claude", description ≤ 1024 characters without XML tags and in the third
person, references one level deep from `SKILL.md`, a contents list in any
reference over 100 lines, no dated instructions — apply to every profile and
live in `POLICY.md`.

The profile does not claim that a phrase always degrades output, or predict
latency. Findings are scoped to the cited guidance and the reviewed workflow.

## 6. Model-fit finding format

```text
[Minor · Defect · Observed] Instruction conflicts with the claude profile
Evidence: SKILL.md:42 — "Before returning, double-check everything."
Profile: claude, resolved from host: Claude Code
Impact: Current Claude models already self-verify; an explicit re-check instruction causes over-verification.
Fix: Remove it, or replace it with a concrete gate: 'Continue only when <command> exits 0'.
Owner: Readiness
```

## 7. Adding a profile

A new profile needs a vendor-published prompting page for that model family,
cited with the date it was read, and for each pattern: the phrase, the effect
the page describes, a replacement, and a severity. A profile without a source
is opinion presented as evidence; the earlier `sol5.6` and `gemini3.8`
profiles were removed for that reason.
