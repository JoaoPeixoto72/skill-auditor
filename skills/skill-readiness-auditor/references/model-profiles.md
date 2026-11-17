# Model profiles

## Contents

1. What a profile is
2. Resolution
3. Universal principles (every profile)
4. `generic`
5. `claude`
6. Model and harness: what a skill cannot guarantee
7. Model-fit finding format
8. Adding a profile

---

## 1. What a profile is

A profile lists instruction patterns that a model family's **vendor has
published** as helping or hurting. It is readiness guidance, not security
policy, and every rule in it cites the page it comes from. A family without
such a page has no profile: it is audited as `generic`.

A model-fit finding requires an active profile, the literal phrase, its
operational effect, and a replacement. `scripts/readiness-audit.py` detects the
phrases mechanically in `SKILL.md`, `POLICY.md` and every Markdown reference
the workflow resolves. A phrase inside a fenced block or an inline code span is
an illustration and is not reported, which is why the phrases below are in
backticks.

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
do not propose `model: claude` or `model: generic`, because the harness would
reject it.

## 3. Universal principles (every profile)

- **Explicit conditions** — "If a referenced path does not exist, record a
  Major finding", not "handle missing paths appropriately".
- **Bounded procedures** — "at most five skills per batch", not "as many as
  necessary".
- **Observable outcomes** — "run the parser; non-zero exit means invalid
  frontmatter", not "ensure it looks valid".
- **Rules separate from examples** — an example illustrates a rule and does
  not add one silently.
- **Failure behaviour defined** — missing command, parse failure, missing
  file, ambiguous target.
- **One authority** — no pair of rules that contradict ("never ask" / "ask
  whenever unsure"); give the order instead.

## 4. `generic`

Only the universal principles. A phrase is reported only when it creates an
unbounded loop, a contradiction, unverifiable behaviour, or no completion
condition. Family-specific preferences are not defects here.

## 5. `claude`

Sources, read 2026-11-17:

- Prompting best practices (current models) —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices
- Prompting Claude Fable 5.2 —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-fable-5-2
- Prompting Claude Opus 5.5 —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-opus-5-5
- Prompting Claude Opus 5 and Sonnet 5 (still the base for those models) —
  https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-opus-5
- Best practices for Claude Code —
  https://code.claude.com/docs/en/best-practices
- Skill authoring best practices —
  https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- Lydia Hallie (Anthropic), "Rethinking Claude Code best practices", AI
  Engineer, 2026-11-12 — https://www.youtube.com/watch?v=vlfCjWuv4es

The pages for Sonnet 5.5 and Haiku 5.5 were not read for this profile; a rule
specific to those models is out of scope until they are.

What changed from the models most skills were first written for, and what the
audit reports:

| Pattern | Why it now hurts | Source | Severity | Replacement |
|---|---|---|---|---|
| All-caps emphasis: `IMPORTANT`, `CRITICAL`, `NEVER`, `ALWAYS`, `MUST`, `DO NOT` (one finding per file) | Current models follow a plainly worded line; emphasis makes them over-apply it. "If it's a rule that can't bend, turn it into a hook or a deny rule" | Claude Code best practices, "What you can stop doing"; prompting best practices | Minor | The rule in normal case with its reason; a hook or deny rule for a rule with no exceptions |
| `If in doubt, use X`, `default to using X` | Blanket defaults cause over-triggering | Prompting best practices | Minor | Name the situations where X helps |
| `double-check everything`, `verify your work` (a re-check with no criterion) | Over-verification; what helps is a check that comes back pass or fail | Prompting best practices (Opus 5 exception); Claude Code best practices, "Give Claude a check to run" | Minor | `Continue only when <command> exits 0` |
| `think hard`, `think carefully`, `be thorough` | Effort is the control; these are ordinary words. On Opus 5.5 removing a `think carefully before answering` line made replies start sooner with no clear quality loss | Claude Code best practices; Prompting Opus 5.5 | Minor | Remove; set `effort:` (`ultrathink` for one turn) |
| `don't be lazy`, `keep going until`, `loop until done` | Current models carry an agreed task through; these lines cause over-work | Claude Code best practices | Minor | A finish line that passes or fails; `/goal` or a `Stop` hook that exits 2 |
| `write out your reasoning`, `show your chain of thought` | Opus 5.5 and Fable 5.2 can decline it as `reasoning_extraction` | Prompting Opus 5.5; Prompting Fable 5.2 | Major | A short explanation of the answer, or a summary of the actions taken |
| `answer without deliberating`, `do not think` | Thinking is always on in Opus 5.5; on Fable 5.2 the line did not stop thinking at medium effort and above | Prompting Opus 5.5; Prompting Fable 5.2 | Minor | Remove; lower `effort:` |
| `always spawn subagents`, `delegate every …` | Fable 5.2 delegates readily when prompts invite it; subagents can be most of a session's cost | Prompting Fable 5.2, "Set expectations for subagents" | Minor | When delegation is worth it, and how to brief the subagent |
| `only report high-severity`, `be conservative`, `don't nitpick` | Sonnet 5 and Opus 5 follow the filter literally and drop real findings | Prompting Opus 5 / Sonnet 5 | Minor | A concrete bar: report what could cause incorrect behaviour; skip style |
| A line that opens with `Never` and gives no scope or reason | Fable 5.2 treats "never" as absolute and may hold routine work | Prompting Fable 5.2, "Keep caution from piling up" | Nit | The reason and the exception, or an approval rule ("ask before deleting files") |

No longer reported:

- **"Use a subagent to review / verify".** A reviewer with a fresh context is
  recommended ("it isn't swayed by the reasoning that produced the code");
  it is not a re-check by the same session.
- **"Give a one-line update every few tool calls".** Fable 5.2's page offers
  exactly this line for interactive use. Progress instructions are fine where
  a person is watching.

Also from these pages, reviewed semantically (no mechanical detector):

- **Only what Claude cannot see.** "The `CLAUDE.md` rule applies to skills
  too: only write down what Claude can't find on its own." Stack, file layout
  and general practice are noise; a deploy process, a misleading directory or
  a decision not recorded in the repository are not.
- **Literal scope** (Sonnet 5, Fable 5.2): an instruction is not generalised
  from one item to others — state the scope ("every section, not just the
  first"). Writing-style limits ("20 words per sentence") are followed so
  closely on Fable 5.2 that prose turns choppy.
- **Accumulated caution** (Fable 5.2): notes such as "never retry" or "stop at
  the first error" keep being followed after their reason is gone. Name the
  steps that need no approval; be specific about the ones that do.
- **Positive instructions and examples beat prohibitions**: show the wanted
  output rather than a list of "don't".
- **Explain why**: a rule with its reason generalises; a bare rule does not.

### Where the sources disagree

The skill-authoring page still shows Claude suggesting stronger language such
as `MUST filter`, and a template that begins `ALWAYS use this exact template`.
The newer Claude Code best practices and the model pages say the opposite for
current models. The audit follows the newer pages and says so in the finding.

The format's own rules — name ≤ 64 characters without "anthropic" or
"claude", description ≤ 1024 characters without XML tags and in the third
person, references one level deep from `SKILL.md`, a contents list in any
reference over 100 lines, no dated instructions — apply to every profile and
live in `POLICY.md`.

The profile does not claim that a phrase always degrades output, or predict
latency. Findings are scoped to the cited guidance and the reviewed workflow.

## 6. Model and harness: what a skill cannot guarantee

Claude Code divides instructions into two kinds. A skill, `CLAUDE.md` or a
prompt is read by the model, which "usually follows your commands … but
there's no guarantee". A hook, a deny rule, the sandbox or a managed setting
is applied by Claude Code every time. The talk's test for which kind a rule
needs: *if Claude gets this wrong once, can I take it back?* These checks apply
to every Claude-hosted skill, under `POLICY.md` §15a:

| Check | Finding |
|---|---|
| A prohibition whose subject cannot be undone (secrets, deletion, push, deploy, publish, send, executing untrusted code, installing, fetching) exists only as prose — no matching `disallowed-tools`, no skill or plugin `PreToolUse` hook, and, for outbound actions, no `disable-model-invocation` | Minor · Concern · Inferred |
| A skill runs a command with an effect outside the working copy (`git push`, `npm publish`, `terraform apply`, …) without `disable-model-invocation: true` | Minor · Concern |
| A hook on a blocking event (`PreToolUse`, `Stop`, `TaskCompleted`, …) fails with exit 1 and never exits 2 or prints a JSON decision — Claude Code treats exit 1 as non-blocking | Major · Defect |
| A hook on a blocking event is `type: prompt` or `type: agent` — another model decides, so it is not deterministic | Nit · Suggestion |

Limits worth knowing when proposing a fix: a deny rule sees the tool call, not
what a script then opens; only the sandbox confines child processes; hooks and
MCP servers run outside the sandbox. `disallowed-tools` in a skill clears at
the next user message, while a skill's `hooks:` stay registered for the rest of
the session. A plugin-level hook counts as backing for a skill of that plugin,
which is why the prose-only check is `Inferred`: the audit cannot prove the hook
covers that exact rule.

## 7. Model-fit finding format

```text
[Minor · Defect · Observed] All-caps emphasis written for older models
Evidence: POLICY.md:106 — "34 marker(s) (MUST, MUST NOT) on lines 106, 108, …"
Profile: claude, resolved from host: Claude Code
Impact: Current models follow a plainly worded line; emphasis makes them over-apply the rule.
Fix: Write the rule in normal case with its reason. A rule that can have no exception belongs in a hook or a deny rule.
Owner: Readiness
```

## 8. Adding a profile

A new profile needs a vendor-published prompting page for that model family,
cited with the date it was read, and for each pattern: the phrase, the effect
the page describes, a replacement, and a severity. A profile without a source
is opinion presented as evidence; the earlier `sol5.6` and `gemini3.8`
profiles were removed for that reason.
