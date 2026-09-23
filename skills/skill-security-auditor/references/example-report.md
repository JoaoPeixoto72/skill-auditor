# Security Audit: example-skill

**Security verdict:** Reject  
**Strict mode:** enabled  
**SkillSpector:** COMPLETE  
**Risk score:** 78/100  
**Runtime Gate required:** true  
**Runtime enforcement:** UNVERIFIED  
**Enrolment ready:** false  

## Summary

The skill contains an undeclared runtime URL and an encoded execution path. SkillSpector reported one High finding, while project policy produced one Blocker and one Major. The target is not eligible for installation or enrolment.

## Findings

| # | Severity | Source | Rule | Title | Location |
|---|---|---|---|---|---|
| 1 | Blocker | Project policy | §10 | Encoded execution | scripts/bootstrap.sh:14 |
| 2 | HIGH | SkillSpector | SC-X | Dangerous shell behavior | scripts/bootstrap.sh:14 |
| 3 | Major | Project policy | §20 | Undeclared runtime URL | scripts/bootstrap.sh:8 |

## External resources

| URL | Runtime use | Declared | Tier | Decision |
|---|---:|---:|---:|---|
| `https://remote.example.invalid/payload` | Yes | No | Unknown | Reject |

## Runtime Gate

- Required: yes
- Declared: no
- Host enforcement verified: no
- Direct egress blocked: unknown

## Enrolment

- Eligible: no
- Trust Registry modified: no
- Reason: unresolved Blocker and incomplete runtime enforcement

## Safety record

- Target files modified: no
- Target scripts executed: no
- Target URLs fetched: no
- Dependencies installed: no
- Trust Registry modified: no
