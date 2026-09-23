# skill-auditor v5.0

[![CI](https://github.com/JoaoPeixoto72/skill-auditor/actions/workflows/test.yml/badge.svg)](https://github.com/JoaoPeixoto72/skill-auditor/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Antigravity%20%7C%20Claude%20Code%20%7C%20Codex%20CLI-orange.svg)](#installation)

Enterprise-grade audit suite, release gate, and runtime integrity governor for Agent Skills.

---

## Overview

`skill-auditor` guarantees that Agent Skills are well-written, structurally valid, model-compatible, secure against prompt injection and data exfiltration, and tamper-evident during execution.

It enforces the fundamental architectural principle: **One concern, one owner, independent binary evidence**.

Instead of a monolithic reviewer trying to assess syntax and malware simultaneously, `skill-auditor` separates the problem into three decoupled skill owners plus an active runtime integrity gate:

```
skill-auditor/
├── skills/
│   ├── skill-readiness-auditor/     # Owner 1: Instruction quality, triggers & structure
│   ├── skill-security-auditor/      # Owner 2: Threat defense, anti-injection & URL tiers
│   └── skill-release-gate/          # Decision: Aggregates Owner 1 + Owner 2 into release verdict
└── runtime/                         # Runtime Gate: Bundle hashing, Trust Registry & network governor
```

---

## Components

### 1. `skill-readiness-auditor`
**Answers:** *Is the skill clearly written, structurally complete, properly triggered, portable, and suited for the target model?*
- Evaluates YAML frontmatter, allowed/disallowed tools, and argument hints.
- Validates **Trigger Tests** (requires positive activation prompts and negative near-misses).
- Verifies model profiles (`opus5`, `sol5.6`, `gemini3.8`, `generic`).
- Validates schema compliance (`readiness-report.schema.json`).
- Deterministic linter: `scripts/readiness-audit.py` (read-only, fast, zero network).

### 2. `skill-security-auditor`
**Answers:** *Is the skill safe to install, enable, sign, or enrol in a production environment?*
- Evaluates prompt injection risks, supply-chain vulnerabilities, and dangerous permissions.
- Enforces strict **External Resource Tiers**:
  - **Tier 0**: Documentation / references (blocked from programmatic runtime fetch).
  - **Tier 1**: Immutable pinned assets (SHA-256 integrity hash required).
  - **Tier 2**: Dynamic schema-validated data feeds (strict envelope and schema).
  - **Tier 3**: Signed executable scripts / updates (Ed25519 cryptographic signatures).
- Optional static scanner integration (e.g. NVIDIA SkillSpector).
- Produces SARIF and JSON security evidence (`security-report.schema.json`).

### 3. `skill-release-gate`
**Answers:** *Should this skill be installed, signed, enrolled, or published?*
- Combines the independent JSON reports from `skill-readiness-auditor` and `skill-security-auditor`.
- Applies declarative binary decision logic: a failure in either owner results in a blocked release.
- Unlinkable from target directives: input reports are treated strictly as data, never executable instructions.

### 4. `runtime/` — Runtime Integrity Gate v2
**Guarantees:** *Runtime tamper-resistance and outbound network governance.*
- **Deterministic Bundle Hashing**: Calculates a canonical SHA-256 fingerprint of the skill bundle.
- **Drift Detection**: Any post-enrollment file addition, modification, or symlink manipulation immediately triggers quarantine.
- **Trust Registry**: Atomic state management for enrolled, quarantined, and verified skills (`trust-registry.mjs`).
- **Network Governor**: Intercepts outbound HTTP/HTTPS requests at runtime (`host-interceptor.mjs`), validating against declared external resource tiers, enforcing payload size limits, blocking loopback/private IPs, and preventing rug-pull attacks.

---

## Installation

### As a Plugin in Google Antigravity
Clone directly into your project's `.agents/plugins/` directory:
```bash
git clone https://github.com/JoaoPeixoto72/skill-auditor.git .agents/plugins/skill-auditor
```
All 3 skills are automatically discovered and mounted by Antigravity.

### As a Plugin in Claude Code
Clone into `.claude/plugins/`:
```bash
git clone https://github.com/JoaoPeixoto72/skill-auditor.git .claude/plugins/skill-auditor
```

### Standalone Skills
If you prefer installing individual skills without the plugin wrapper:
```bash
# Example for Claude Code
cp -r skills/skill-readiness-auditor ~/.claude/skills/
cp -r skills/skill-security-auditor ~/.claude/skills/
cp -r skills/skill-release-gate ~/.claude/skills/

# Example for Google Antigravity
cp -r skills/skill-readiness-auditor ~/.gemini/config/skills/
cp -r skills/skill-security-auditor ~/.gemini/config/skills/
cp -r skills/skill-release-gate ~/.gemini/config/skills/
```

---

## Usage

### 1. Run Mechanical Readiness Audit
```bash
python skills/skill-readiness-auditor/scripts/readiness-audit.py <path-to-skill>
```
To generate machine-readable JSON:
```bash
python skills/skill-readiness-auditor/scripts/readiness-audit.py <path-to-skill> --format json --output readiness-report.json
```

### 2. Run Security Audit
```bash
python skills/skill-security-auditor/scripts/security-audit.py <path-to-skill> --format json --output security-report.json
```
For strict mode (fails on warnings or missing scanners):
```bash
python skills/skill-security-auditor/scripts/security-audit.py <path-to-skill> --strict
```

### 3. Evaluate Release Gate
```bash
python skills/skill-release-gate/scripts/release-gate.py \
  --readiness-report readiness-report.json \
  --security-report security-report.json \
  --action install
```

### 4. Running the Runtime Integrity Gate (Node.js)
```javascript
import { RuntimeGate } from './runtime/runtime-gate.mjs';
import { TrustRegistry } from './runtime/trust-registry.mjs';

const registry = new TrustRegistry('./registry.json');
const gate = new RuntimeGate({ registry });

// Check and intercept before running skill commands:
const decision = await gate.evaluateSkillExecution('./path/to/skill');
if (!decision.allowed) {
  throw new Error(`Execution blocked: ${decision.reason}`);
}
```

---

## Testing

The project has comprehensive test coverage (119 automated tests):
- **67 Python tests** for readiness, security, and release gate policies.
- **52 Node.js tests** for runtime hashing, network governance, trust registry, and E2E lifecycle scenarios.

Run all tests:
```bash
npm test
```
Or individually:
```bash
# Node.js tests (built-in runner, zero npm dependencies)
npm run test:node

# Python tests
npm run test:py
```

---

## License

[MIT](LICENSE) © 2026 Joao Costa
