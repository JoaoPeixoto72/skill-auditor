# skill-auditor v4.2 (hybrid)

An Agent Skill that audits other Agent Skills. It combines:

- **Semantic review** — model-aware, with externalized policy, a Trigger Tests suite, and a rich finding model. Inspired by `JoaoPeixoto72/Skill-Reviewer`.
- **Mechanical linter** — `scripts/audit.sh`, deterministic, ~ms, catches structural regressions without spending tokens.
- **Claim verification** (§10, `--depth deep`) — runs the cheapest command that could refute what the skill asserts about its repo. This is the half a structural audit cannot reach: a skill can conform to every rule in `POLICY.md` and still say "34 components" over a folder holding 39. Conformance and truth are different audits.

## Layout

```
skill-auditor/
├── SKILL.md                       # entry point (thin)
├── POLICY.md                      # authoritative rules (§1–§11)
├── scripts/
│   └── audit.sh                   # mechanical linter (frontmatter, hooks, refs, limits,
│                                  # inventory counts, absolute paths, skill pointers)
└── references/
    ├── model-profiles.md          # opus5 / sol5.6 / gemini3.8 / generic
    ├── finding-model.md           # Type / Severity / Confidence / Verdict
    ├── example-report.md          # canonical output format + Trigger Tests
    ├── anti-injection.md          # statement + heuristics
    └── fixtures/
        └── hostile-skill/         # fixture for testing detection
```

## Install

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

The repo's `install.sh` symlinks it alongside the `ux-*` skills, so it stays in sync with `core/`.

## Invoke

```
/skill-auditor <path> [--depth quick|standard|deep] [--model opus5|sol5.6|gemini3.8|generic]
```

Examples:
- `/skill-auditor design-skills-v3.1/core/ux-forms` — standard, model resolved from frontmatter.
- `/skill-auditor ./skills --target repo --depth quick` — quick repo sweep.
- `/skill-auditor ./my-skill --depth deep --model sol5.6` — full review with a forced model.

## Linter only (CI hook)

```bash
bash skill-auditor/scripts/audit.sh <path>
```

Exit codes:
- `0` — zero findings, or Minor/Nit only
- `1` — ≥1 Major or Blocker
- `2` — invalid target

## Verdict enum

`Reject` · `Needs revision` · `Approve with nits` · `Ready with suggestions` · `Ready`

Highest severity wins, not the count. Detail in `references/finding-model.md`.

## What v4.1 added

- **Trigger Tests (near-misses)**: every `description` correction must come with positive prompts and negative near-misses (POLICY §2).
- **Session blast radius & hooks**: mechanical and semantic detection of session `hooks:` undocumented in the description (POLICY §9).
- **Forked-subagent consistency**: flags `agent`/`background` declared without `context: fork` (POLICY §6).
- **Updated model profiles**: `gemini3.8` (Antigravity), `sol5.6`, `opus5`.
- **Anti prompt-injection, tested**: explicit statement plus a hostile fixture under `references/fixtures/`.

## Credits

Design inspired by [`JoaoPeixoto72/Skill-Reviewer`](https://github.com/JoaoPeixoto72/Skill-Reviewer). Mechanical layer originally from `design-skills-v3`.
