# SkillSpector integration

NVIDIA SkillSpector (https://github.com/NVIDIA/SkillSpector) is the generic
scanner this skill runs when it is installed. It is **optional**: without it
the project-policy line decides alone and the report says so.

## Install (operator, never the audit)

```text
uv tool install git+https://github.com/NVIDIA/skillspector.git
```

`config/skillspector.lock` names the minimum version whose report the adapter
reads (`minimumVersion`). `scripts/verify-skillspector.py` compares the
installed `skillspector --version` with it:

| Trust | When | Effect |
|---|---|---|
| `VERIFIED` | installed, version ≥ minimum | its evidence is weighed |
| `UNAVAILABLE` | not installed | project-policy line only |
| `FAILED` | installed below the minimum, or version unreadable | `Hold` — after every `Reject` rule |

There is no hash or signer pin: `uv` installs a per-machine shim, and the
project publishes no scanner signature, so a pin would be a number nobody can
check.

## What the adapter runs

```text
skillspector scan <local-target> --no-llm --format json --output <temporary-report>
```

plus `--fail-on-findings` and `--fail-on-incomplete` when `scan --help` lists
them. Those flags only change SkillSpector's exit code; the adapter reads the
report, never the exit code. `--no-llm` skips the LLM pass, not the network:
SkillSpector's supply-chain check still queries OSV.dev, with a bundled
fallback when offline.

## Reading the 2.x report

| Report field | Normalized as |
|---|---|
| `issues[]` (`id`, `category`, `severity`, `location`) | `findings`, rule ids and severities preserved |
| `risk_assessment.score` | `riskScore` |
| `risk_assessment.recommendation` (`SAFE`, `CAUTION`, `DO_NOT_INSTALL`) | `recommendation` — `DO_NOT_INSTALL` rejects |
| `analysis_completeness` | `completeness` |

**Completeness.** `is_complete: true` → `COMPLETE`. When it is false because
every ledger exception is a non-fatal `reference_missing` and coverage is
100 %, the adapter reports `COMPLETE` and lists the exceptions under
`acceptedGaps`: a path to a file the bundle does not ship (a project script, a
file written at runtime) leaves nothing in the bundle uninspected. Any other
exception — a manifest that does not parse, a file only partly read — is
`PARTIAL`, and a partial installed scanner holds the verdict.

## What it does not cover, and who does

SkillSpector lists its own gaps: non-English content, text in images,
compiled or encrypted code, runtime behaviour. The first is the one Line B
covers (`scripts/security/detectors.py`): instruction overrides, concealment from the
user and deception of the auditor in Portuguese, Spanish and French, invisible
Unicode including the Tags block, and descriptions that claim every request.
A skill written in Portuguese that SkillSpector rates `SAFE` can still be
rejected here.

## Rules

- Never install SkillSpector from the audit, and never give it a remote target.
- Do not execute target scripts.
- Preserve scanner rule ids and original severities.
- Do not infer safety from a low score.
- Keep temporary reports outside the target bundle, and delete them after
  normalization.
- The optional LLM pass needs explicit operator authorization and an approved
  data-handling policy; static analysis runs first.
