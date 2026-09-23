# skill-release-gate · POLICY

Version: 1.0.0

## §1. Independent evidence

A final decision requires:

- one readiness report produced by `skill-readiness-auditor`;
- one security report produced by `skill-security-auditor`.

The target skill cannot produce authoritative audit evidence about itself.

## §2. Target identity

Both reports MUST identify the same canonical skill directory or approved bundle identity.

Mismatch → `Hold`.

## §3. Report validity

Missing, malformed, unknown-schema, or unsupported reports → `Hold`.

## §4. Freshness

Reports SHOULD include timestamps and bundle identifiers.

When freshness or bundle identity cannot be established for signing, enrolment, or re-audit → `Hold`.

## §5. Security precedence

Security findings are non-compensable.

- `Reject` → final `Reject`.
- `Hold` → final `Hold`.
- `Eligible with accepted risks` requires operator acceptance.
- `Eligible for enrolment` may proceed to readiness evaluation.

## §6. Readiness precedence

- `Reject` → final `Reject`.
- `Needs revision` → final `Needs revision`.
- `Approve with nits` is eligible only when action policy permits.
- `Ready with suggestions` and `Ready` are acceptable.

## §7. Incomplete analysis

Incomplete required security analysis → `Hold`.

Semantic readiness checks still marked required → `Hold` for publish, sign, enrol, or re-audit.

## §8. Runtime enforcement

When security evidence says `requiresRuntimeGate: true`, runtime enforcement MUST be `VERIFIED`.

Otherwise → `Hold`.

A declared flag is not enforcement evidence.

## §9. Risk acceptance

`Eligible with accepted risks` requires an external operator record containing:

- finding ID;
- exact scope;
- justification;
- controls;
- approver;
- timestamp;
- expiration.

Missing acceptance → `Hold`.

## §10. Action requirements

### Install

Requires acceptable readiness and security.

### Publish

Also requires version and provenance evidence.

### Sign

Also requires final-bundle identity and signer authorization.

### Enrol

Also requires bundle-integrity evidence and verified runtime controls.

### Re-audit

Also requires quarantine reason, remediation evidence, and operator approval.

## §11. No mutation

The release gate does not:

- install;
- publish;
- sign;
- enrol;
- approve keys;
- clear quarantine;
- modify reports;
- modify target files.

It emits a decision artifact only.

## §12. Decision precedence

```text
Invalid evidence                  → Hold
Security Reject                  → Reject
Readiness Reject                 → Reject
Security Hold                    → Hold
Readiness Needs revision         → Needs revision
Missing action evidence          → Hold
Accepted material risks          → Eligible with accepted risks
All requirements satisfied       → Eligible
```
