# Skill Release Gate: example-skill

**Action:** enrol  
**Final decision:** Hold  
**Readiness verdict:** Ready  
**Security verdict:** Eligible for enrolment  

## Decision

The skill passed readiness and security review, but enrolment cannot proceed because the required Runtime Gate attestation is missing.

## Evidence

| Evidence | State |
|---|---|
| Readiness report | Valid |
| Security report | Valid |
| Target identity | Match |
| Security completeness | Complete |
| Runtime Gate required | Yes |
| Runtime enforcement | Unverified |
| Bundle integrity | Present |
| Operator approval | Not required |

## Blocking reasons

1. Runtime Gate enforcement is required but not verified.

## Next actions

1. Obtain privileged-host runtime attestation.
2. Re-run the release gate.
3. Perform enrolment through the privileged operator process.

## Mutations

- Target modified: no
- Reports modified: no
- Trust Registry modified: no
- Skill installed: no
