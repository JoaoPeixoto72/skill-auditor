# Trust Registry enrolment policy

## Eligibility

A skill is eligible for enrolment only when:

- strict analysis is complete;
- SkillSpector evidence is complete;
- no unresolved Blocker or Critical exists;
- no unresolved High or Major exists;
- the complete bundle was inspected;
- external resources are valid;
- runtime enforcement is verified when required;
- bundle-integrity evidence exists;
- required signature verification succeeded;
- no unexplained sensitive behavior remains.

## States

```text
UNREGISTERED
    ↓ privileged enrolment
TRUSTED
    ↓ policy or integrity violation
QUARANTINED
    ↓ formal re-audit
REAUDIT_PENDING
    ↓ operator approval
TRUSTED
```

Ordinary registration cannot restore a quarantined skill.

## Separation of authority

The security auditor:

- produces evidence;
- does not modify the registry;
- does not add trusted keys;
- does not approve itself;
- does not restore trust.

The privileged host owns enrolment and quarantine transitions.

## Runtime attestation

A network-capable skill requires host evidence that:

- all network operations are intercepted;
- direct egress is blocked;
- exact URLs are authorized;
- redirects are controlled;
- local bundle integrity is checked;
- quarantine revokes network capability.

A voluntary call to a gate function is not sufficient enforcement.

## Risk acceptance

Accepted risk requires:

- finding identifier;
- exact scope;
- justification;
- compensating controls;
- approver;
- timestamp;
- expiration.

The following cannot be accepted through routine suppression:

- credential theft;
- deliberate exfiltration;
- Trust Registry tampering;
- Runtime Gate bypass;
- hidden prompt injection;
- invalid signature presented as trusted;
- unexplained obfuscated execution.
