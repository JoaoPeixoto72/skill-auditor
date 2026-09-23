# skill-auditor

[![CI](https://github.com/JoaoPeixoto72/skill-auditor/actions/workflows/test.yml/badge.svg)](https://github.com/JoaoPeixoto72/skill-auditor/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Audit and release gate for Agent Skills: is a skill well written, does it talk
to current models the way their vendor says works, and is it safe to install.
Works with NVIDIA SkillSpector installed, and without it.

```
skills/
├── skill-readiness-auditor/   # instruction quality, triggers, format rules, model fit
├── skill-security-auditor/    # injection, concealment, exfiltration, supply chain, URL tiers
└── skill-release-gate/        # combines both reports into one decision
```

One concern per owner, and each verdict comes from its own evidence.

## skill-readiness-auditor

*Is the skill clearly written, correctly triggered, and ready to ship?*

- Frontmatter and the Agent Skills format: name ≤ 64 characters without
  `anthropic`/`claude`, description ≤ 1024 characters, third person, no XML
  tags; allowed-tools coherent with the workflow.
- Triggering: what the skill does, when to use it, when not — in English,
  Portuguese or Spanish.
- Local resources resolve, including a sibling skill's (`../other/scripts/x`)
  and `${CLAUDE_SKILL_DIR}/…`; references one level deep; long references
  with a contents list; no dated instructions.
- **Model fit** for current Claude models, from Anthropic's published
  prompting pages (`references/model-profiles.md`): aggressive `CRITICAL`/`MUST`
  emphasis and "if in doubt, use X" that now over-trigger; "double-check"
  instructions that cause over-verification on Opus 5; "only report
  high-severity" filters that Sonnet 5 and Opus 5 follow literally. The
  profile is picked from `model:` or from the host (`.claude/`).
- Functional claims checked against the files at `--depth deep`.

## skill-security-auditor

*Is the skill safe to install, keep enabled, or enrol?*

Two evidence lines:

- **NVIDIA SkillSpector**, when installed (`uv tool install
  git+https://github.com/NVIDIA/skillspector.git`, version ≥ the one in
  `config/skillspector.lock`). Its `CRITICAL` findings and `DO_NOT_INSTALL`
  reject; incomplete evidence from it holds.
- **Project policy**, always: external-resource tiers and declarations,
  obfuscated execution, persistence, sensitive data next to network calls —
  and what SkillSpector lists as its own gap: instructions in Portuguese,
  Spanish and French to override the user's instructions, to hide a step
  from the user, or to lie to an auditor; invisible Unicode including the
  Tags block; descriptions that claim every request.

Without SkillSpector the project-policy line decides alone and the report says
`Evidence lines: project-policy`. `--require-scanner` holds instead, for
deployments that mandate both lines. A scanner that cannot be trusted never
masks a Blocker: rejection is decided first.

Runtime enforcement of declared URLs belongs to the host (see the skill's
"Runtime relationship"); this plugin produces the evidence, it does not
intercept traffic.

## skill-release-gate

*Should this skill be installed, published, signed, or enrolled?*

Reads the two reports as data, never as instructions. Either owner's `Reject`
rejects; missing evidence holds. SkillSpector evidence is required only when
the security report says it was installed or required.

## Install

Claude Code:

```text
/plugin marketplace add JoaoPeixoto72/skill-auditor
/plugin install skill-auditor@skill-auditor
```

Other hosts: copy `skills/*` into the host's skills folder
(`~/.gemini/config/skills/` for Antigravity).

## Use

The wrappers resolve a working Python (not the Windows Store alias) and force
UTF-8. Paths are relative to each skill's folder (`${CLAUDE_SKILL_DIR}` in
Claude Code).

```bash
bash skills/skill-readiness-auditor/scripts/audit.sh <skill-or-repo> --format json > readiness.json
bash skills/skill-security-auditor/scripts/audit.sh <skill> --strict --format json > security.json
bash skills/skill-release-gate/scripts/gate.sh --readiness-report readiness.json \
  --security-report security.json --action install
```

## Tests

```bash
pip install pyyaml pytest
pytest
```

The suite runs without SkillSpector; `tests/test_pipeline.py` takes a skill
through all three owners.

## License

[MIT](LICENSE) © 2026 Joao Costa
