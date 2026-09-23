# Security finding model

## Project finding

```text
[Severity · Type · Confidence] Title
Evidence: path:line — "sanitized excerpt"
Impact: concrete security consequence
Fix: concrete remediation
Owner: Security
Source: Project policy | SkillSpector | Semantic review
Rule: policy section or scanner rule ID
```

## Project severity

- **Blocker** — unsafe to install or a security boundary can be bypassed.
- **Major** — material risk requiring correction or explicit operator decision.
- **Minor** — bounded risk or hardening defect.
- **Nit** — low-impact consistency issue.

## External severity

Preserve SkillSpector severity exactly:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

Do not silently downgrade it.

## Confidence

- **Observed** — direct file, scanner, parser, hash, or signature evidence.
- **Inferred** — supported by indirect evidence.
- **Unknown** — cannot be safely established in scope.

## Verdict

### Reject

- Blocker;
- unresolved Critical;
- established malicious behavior;
- credential theft;
- deliberate exfiltration;
- hidden prompt injection;
- unauthorized persistence;
- Runtime Gate bypass;
- invalid trusted signature.

### Hold

- scanner unavailable;
- analysis incomplete;
- unresolved High or Major;
- executable content skipped;
- required runtime enforcement unverified;
- required provenance unverified.

### Eligible with accepted risks

- analysis complete;
- no Blocker or Critical;
- remaining material risks explicitly accepted by an operator;
- compensating controls documented.

### Eligible for enrolment

- complete analysis;
- no unresolved material security finding;
- valid resource policy;
- verified runtime enforcement where required;
- integrity and provenance requirements satisfied.
