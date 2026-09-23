# Readiness Audit: example-skill

**Readiness verdict:** Needs revision
**Depth:** deep
**Model profile:** claude
**Profile resolved from:** `host: Claude Code`
**Reviewed:** `.agents/skills/example-skill/SKILL.md`
**Security status:** Handoff required
**Release status:** Needs revision

## Summary

The skill has valid frontmatter and a coherent central workflow, but its description does not distinguish readiness review from security review. One documented command is also incompatible with the declared Bash permission pattern.

The functional claims pass found three claims: one confirmed, one refuted, and one unverified. The refuted command-permission claim produces the highest readiness finding, so the verdict is `Needs revision`.

A separate security review is required because the skill declares shell access and references an external URL. This report does not classify those capabilities as safe or malicious.

## Dimensions

| Dimension | State | Notes |
|---|---|---|
| Frontmatter | Pass | YAML parses and required fields exist |
| Description | Needs revision | Missing negative boundary |
| Triggering | Needs revision | Overlaps security auditor |
| Workflow coverage | Pass | Central promises map to workflow steps |
| Instruction quality | Pass | Instructions are ordered and testable |
| Context | Pass | Runtime and working-directory assumptions declared |
| Permission coherence | Fail | Bash pattern does not match documented invocation |
| Portability | Pass with note | POSIX-only support is explicitly declared |
| Model fit | Pass | No profile-specific defects |
| Local resources | Pass | All referenced files resolve |
| Functional claims | Fail | One claim refuted |
| Output contract | Pass | Markdown report format defined |
| Repository routing | Pass | Alternative skill is installed |
| Security review | Not performed | Handoff required |

## Findings

| # | Severity | Type | Confidence | Title | Location |
|---|---|---|---|---|---|
| 1 | Major | Defect | Observed | Description does not distinguish readiness from security review | `SKILL.md:3` |
| 2 | Major | Defect | Observed | Bash permission does not match the documented command | `SKILL.md:11,48` |
| 3 | Minor | Concern | Inferred | Repository-root resource coupling is not documented | `SKILL.md:62` |
| 4 | Nit | Suggestion | Observed | Output heading differs from the declared report format | `SKILL.md:105` |

## Finding details

### 1. Description does not distinguish readiness from security review

**[Major · Defect · Observed] Description does not distinguish readiness from security review**

- Evidence: `SKILL.md:3` — `"Audit Agent Skills before installation or release."`
- Impact: requests such as “is this skill safe to install?” may route to a readiness-only review and be mistaken for a security assessment.
- Fix: state that this skill checks instruction quality and model compatibility, and route malicious-code or installation-safety requests to `skill-security-auditor`.
- Owner: Readiness
- Policy: §6 Trigger discrimination

### 2. Bash permission does not match the documented command

**[Major · Defect · Observed] Bash permission does not match the documented command**

- Evidence: `SKILL.md:11` — `"Bash(scripts/check.sh:*)"`
- Evidence: `SKILL.md:48` — `"Run bash scripts/check.sh <target>."`
- Impact: the workflow invokes the script through `bash`, but the declared pattern begins with the script path. The target adapter may block the central mechanical check.
- Fix: declare a permission matching the complete invocation, such as `Bash(bash scripts/check.sh:*)`, if supported by the target adapter.
- Owner: Readiness
- Policy: §14 Permission coherence

### 3. Repository-root resource coupling is not documented

**[Minor · Concern · Inferred] Repository-root resource coupling is not documented**

- Evidence: `SKILL.md:62` — `"Read schemas/report.schema.json."`
- Evidence: `test -f <skill>/schemas/report.schema.json` → exit 1
- Evidence: `test -f <repo>/schemas/report.schema.json` → exit 0
- Impact: the resource works inside the current repository but may be absent when the skill is installed independently.
- Fix: move the schema into the skill bundle or declare the repository-root packaging dependency.
- Owner: Readiness
- Policy: §16 Local resources

### 4. Output heading differs from the declared report format

**[Nit · Suggestion · Observed] Output heading differs from the declared report format**

- Evidence: `SKILL.md:89` requires `"## Findings"`.
- Evidence: `SKILL.md:105` shows `"## Issues"`.
- Impact: report consumers may need to support two headings.
- Fix: use `## Findings` consistently.
- Owner: Readiness
- Policy: §23 Output contract

## Promise-to-step map

| Description promise | Workflow implementation | State | Evidence |
|---|---|---|---|
| Audit frontmatter | Mechanical audit, step 3 | Covered | `SKILL.md:43-49` |
| Review triggering | Semantic review, step 4 | Covered | `SKILL.md:51-63` |
| Review model fit | Semantic review, step 10 | Covered | `SKILL.md:119-132` |
| Verify functional claims | Claims pass, step 11 | Covered | `SKILL.md:134-160` |
| Audit security before installation | No security workflow exists | Missing | `SKILL.md:3` |

## Claims

| # | Claim | Verification | Result | State |
|---|---|---|---|---|
| 1 | “The skill contains four reference documents.” | `find references -maxdepth 1 -type f -name '*.md' \| wc -l` | `4` | CONFIRMED |
| 2 | “The declared permission allows the mechanical command.” | Compare `Bash(scripts/check.sh:*)` with `bash scripts/check.sh <target>` | Patterns differ | REFUTED |
| 3 | “The workflow supports Python 3.10 and later.” | Current environment reports Python 3.12; earlier versions were not executed | Partial environment evidence only | UNVERIFIED |

## Trigger tests

**State:** Proposed, not executed

### Proposed description

```yaml
description: "Audit Agent Skills for instruction quality, trigger discrimination, model fit, workflow coverage, and portability before commit or release. Do not use for malware detection, supply-chain security, or runtime enforcement; use skill-security-auditor for those concerns."
```

| # | Prompt | Expected routing | Reason |
|---|---|---|---|
| 1 | “Check whether this SKILL.md is ready for release.” | ACTIVATE example-skill | Explicit readiness request |
| 2 | “Review this skill’s trigger description and model compatibility.” | ACTIVATE example-skill | Matches triggering and model-fit scope |
| 3 | “Scan this downloaded skill for credential theft.” | DO NOT ACTIVATE; use skill-security-auditor | Security request |
| 4 | “Review this application pull request.” | DO NOT ACTIVATE; use application auditor | Wrong artifact |
| 5 | “Check whether this skill is ready and safe to install.” | Run readiness and security audits, or use skill-release-gate | Combined intent |

## Security handoff

**Required:** Yes

| Observed capability | Location | Handoff reason |
|---|---|---|
| Shell execution | `SKILL.md:11,48` | Security auditor must assess whether shell capability is proportionate |
| External URL | `references/provider.md:12` | Security auditor must classify the remote resource and its runtime use |

**Recommended next step:** Run `skill-security-auditor` against the complete skill directory.

No remote content was fetched during this readiness review.

## Commands run

- `bash scripts/audit.sh .agents/skills/example-skill`
- `find .agents/skills/example-skill/references -maxdepth 1 -type f -name '*.md'`
- `test -f .agents/skills/example-skill/schemas/report.schema.json`
- `test -f schemas/report.schema.json`

## Skipped checks

| Check | Reason |
|---|---|
| Target-script execution | Readiness audit does not execute untrusted scripts |
| External URL validation | Requires security audit |
| Dependency vulnerability scan | Owned by skill-security-auditor |
| Signature verification | Owned by release/security tooling |
| Runtime network enforcement | Owned by the privileged Runtime Gate |
| Python 3.10 compatibility | Python 3.10 was unavailable in the current environment |

## Top fixes

1. Rewrite the description to distinguish readiness from security review.
2. Correct the Bash permission so it matches the documented invocation.
3. Move the shared schema into the skill bundle or document its packaging contract.
4. Normalize the output heading to `## Findings`.
5. Run `skill-security-auditor` before installation or publication.

## Meta

- Mechanical audit: completed
- Semantic review: completed
- Claims extracted: 3
- Claims confirmed: 1
- Claims refuted: 1
- Claims unverified: 1
- Trigger tests: proposed, not executed
- Target files modified: no
- Target scripts executed: no
- Network requests performed: no

Security certification: Not performed by skill-readiness-auditor.
