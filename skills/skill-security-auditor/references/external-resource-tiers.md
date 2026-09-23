# External-resource tiers

## Tier 0 — human-only documentation

Use for passive references.

Requirements:

- exact HTTPS URL;
- documented purpose;
- no programmatic fetching;
- no use as runtime instructions.

Runtime fetch attempt:

```text
BLOCK → QUARANTINED
```

## Tier 1 — immutable external bytes

Use when the expected bytes must never change.

Requirements:

- exact HTTPS URL;
- `maxBytes`;
- `sha256-<64 hex>`;
- byte-level verification;
- redirect blocking;
- Runtime Gate enforcement.

Hash mismatch:

```text
RUG_PULL_HASH_MISMATCH → QUARANTINED
```

## Tier 2 — dynamic data

Use for legitimate changing data.

Requirements:

- exact HTTPS URL;
- JSON response;
- strict allowed-key schema;
- required keys where applicable;
- response-size limit;
- host-enforced data-channel isolation;
- no promotion into system or developer instructions.

An envelope field is metadata, not isolation by itself.

## Tier 3 — agent-controlling content

Tier 3 can influence planning, instructions, commands, or tool choice.

It is forbidden by default.

Managed exceptions require:

- enterprise authorization;
- exact HTTPS URL;
- Ed25519 signature;
- operator-managed trusted key;
- exact-byte verification;
- response-size limit;
- Runtime Gate enforcement;
- audit logging;
- revocation procedure.

The target skill cannot provide its own trust anchor.
