# SkillSpector integration

SkillSpector is the preferred generic Agent Skill security scanner.

The local adapter runs:

```text
skillspector scan <local-target> --no-llm --format json --output <temporary-report>
```

When supported by the installed version, it also uses:

```text
--fail-on-findings
--fail-on-incomplete
```

## Rules

- Never install SkillSpector automatically.
- Never give SkillSpector a remote target through this skill.
- Do not execute target scripts.
- Preserve scanner rule IDs and original severities.
- Treat incomplete evidence as `Hold`.
- Do not infer safety from a low score.
- Do not infer completeness from exit code alone.
- Keep temporary reports outside the target bundle.
- Delete temporary reports after normalization.

## Scanner states

- `COMPLETE`
- `PARTIAL`
- `UNAVAILABLE`
- `FAILED`

Strict enrolment requires `COMPLETE`.

## Optional LLM analysis

Default:

```text
--no-llm
```

LLM analysis requires explicit operator authorization and an approved data-handling policy.

Static analysis must still run first.

## Version differences

The adapter inspects:

```text
skillspector scan --help
```

It passes strict flags only when supported.

If a flag is unsupported, the adapter enforces equivalent behavior from report evidence where possible and records the omitted flag.
