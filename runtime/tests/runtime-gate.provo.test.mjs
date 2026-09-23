import {
  afterEach,
  beforeEach,
  describe,
  it
} from 'node:test';

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  TrustRegistry,
  calculateBundleHash
} from '../trust-registry.mjs';

import {
  executeRuntimeGate
} from '../runtime-gate.mjs';

let temporaryRoot;
let registryPath;
let skillPath;

function writeSkillFile(name, content) {
  const target = path.join(skillPath, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
}

function tier1Resource(url, content) {
  const hash = crypto
    .createHash('sha256')
    .update(Buffer.from(content))
    .digest('hex');

  return {
    url,
    tier: 1,
    purpose: 'Test immutable content',
    maxBytes: 4096,
    hash: `sha256-${hash}`
  };
}

describe('Runtime Integrity Gate v2', () => {
  beforeEach(() => {
    temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), 'runtime-gate-test-')
    );

    registryPath = path.join(temporaryRoot, 'registry.json');
    skillPath = path.join(temporaryRoot, 'skills', 'test-skill');

    fs.mkdirSync(skillPath, { recursive: true });
    writeSkillFile(
      'SKILL.md',
      '---\nname: test-skill\ndescription: "Test a skill."\nallowed-tools: []\n---\n'
    );
  });

  afterEach(() => {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  });

  it('calculates a deterministic bundle hash', () => {
    writeSkillFile('references/a.md', 'alpha');

    const first = calculateBundleHash(skillPath);
    const second = calculateBundleHash(skillPath);

    assert.equal(first, second);
    assert.match(first, /^[a-f0-9]{64}$/);
  });

  it('quarantines an unregistered skill', async () => {
    const result = await executeRuntimeGate({
      skillName: 'unknown',
      url: 'https://cdn.example.invalid/resource',
      mockBody: 'data',
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'UNREGISTERED_SKILL');

    const registry = new TrustRegistry(registryPath);
    assert.equal(registry.getSkill('unknown').state, 'QUARANTINED');
  });

  it('permits a Tier 1 resource when exact bytes match', async () => {
    const body = Buffer.from([0, 1, 2, 3, 255]);
    const hash = crypto.createHash('sha256').update(body).digest('hex');

    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://cdn.example.invalid/resource.bin',
        tier: 1,
        purpose: 'Binary test resource',
        maxBytes: 4096,
        hash: `sha256-${hash}`
      }]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://cdn.example.invalid/resource.bin',
      mockBody: body,
      registryPath
    });

    assert.equal(result.allowed, true);
    assert.equal(result.tier, 1);
    assert.equal(result.hashVerified, true);
    assert.deepEqual(result.content, body);
  });

  it('detects Tier 1 remote mutation and quarantines', async () => {
    const original = 'approved bytes';
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [
        tier1Resource(
          'https://cdn.example.invalid/resource.txt',
          original
        )
      ]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://cdn.example.invalid/resource.txt',
      mockBody: 'changed bytes',
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'RUG_PULL_HASH_MISMATCH');

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'QUARANTINED'
    );
  });

  it('detects local bundle drift before network use', async () => {
    const body = 'approved';
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [
        tier1Resource(
          'https://cdn.example.invalid/resource.txt',
          body
        )
      ]
    });

    writeSkillFile('scripts/new-file.mjs', 'export const changed = true;\n');

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://cdn.example.invalid/resource.txt',
      mockBody: body,
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'LOCAL_BUNDLE_HASH_MISMATCH');

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'QUARANTINED'
    );
  });

  it('blocks undeclared URLs and quarantines', async () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [
        tier1Resource(
          'https://cdn.example.invalid/allowed.txt',
          'allowed'
        )
      ]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://other.example.invalid/not-allowed',
      mockBody: 'data',
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'UNAUTHORIZED_URL');

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'QUARANTINED'
    );
  });

  it('blocks Tier 0 fetches', async () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://docs.example.invalid/specification',
        tier: 0,
        purpose: 'Human-only documentation',
        maxBytes: 4096
      }]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://docs.example.invalid/specification',
      mockBody: 'documentation',
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'TIER0_FETCH_PROHIBITED');
  });

  it('validates and envelopes Tier 2 data', async () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://api.example.invalid/weather',
        tier: 2,
        purpose: 'Weather data',
        maxBytes: 4096,
        schema: {
          type: 'object',
          requiredKeys: ['temperature', 'condition'],
          allowedKeys: ['temperature', 'condition']
        }
      }]
    });

    const payload = {
      temperature: 22,
      condition: 'clear'
    };

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://api.example.invalid/weather',
      mockBody: payload,
      registryPath
    });

    assert.equal(result.allowed, true);
    assert.equal(result.tier, 2);
    assert.deepEqual(result.envelope.payload, payload);
    assert.equal(result.envelope.isExecutableInstruction, false);
    assert.equal(result.envelope.instructionChannelEligible, false);
  });

  it('rejects unexpected Tier 2 fields', async () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://api.example.invalid/data',
        tier: 2,
        purpose: 'Structured data',
        maxBytes: 4096,
        schema: {
          type: 'object',
          requiredKeys: ['value'],
          allowedKeys: ['value']
        }
      }]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://api.example.invalid/data',
      mockBody: {
        value: 10,
        unexpected: 'not allowed'
      },
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'TIER2_SCHEMA_REJECTED');
  });

  it('verifies a valid Ed25519 Tier 3 signature', async () => {
    const {
      publicKey,
      privateKey
    } = crypto.generateKeyPairSync('ed25519');

    const publicKeyPem = publicKey.export({
      type: 'spki',
      format: 'pem'
    });

    const body = Buffer.from('signed managed payload');
    const signature = crypto.sign(null, body, privateKey).toString('base64');

    const registry = new TrustRegistry(registryPath);
    registry.addTrustedKey('enterprise-key', publicKeyPem);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://managed.example.invalid/payload',
        tier: 3,
        purpose: 'Managed signed payload',
        maxBytes: 4096,
        keyId: 'enterprise-key'
      }]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://managed.example.invalid/payload',
      mockBody: body,
      mockSignature: signature,
      registryPath
    });

    assert.equal(result.allowed, true);
    assert.equal(result.signatureVerified, true);
    assert.equal(result.keyId, 'enterprise-key');
  });

  it('rejects a false Tier 3 signature and quarantines', async () => {
    const {
      publicKey
    } = crypto.generateKeyPairSync('ed25519');

    const publicKeyPem = publicKey.export({
      type: 'spki',
      format: 'pem'
    });

    const registry = new TrustRegistry(registryPath);
    registry.addTrustedKey('enterprise-key', publicKeyPem);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: [{
        url: 'https://managed.example.invalid/payload',
        tier: 3,
        purpose: 'Managed signed payload',
        maxBytes: 4096,
        keyId: 'enterprise-key'
      }]
    });

    const result = await executeRuntimeGate({
      skillName: 'test-skill',
      url: 'https://managed.example.invalid/payload',
      mockBody: 'changed payload',
      mockSignature: Buffer.from('invalid signature').toString('base64'),
      registryPath
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'TIER3_SIGNATURE_INVALID');

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'QUARANTINED'
    );
  });

  it('does not allow ordinary enrolment to clear quarantine', () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'test',
      allowedResources: []
    });

    registry.quarantineSkill('test-skill', 'Test quarantine');

    assert.throws(
      () => registry.enrolSkill('test-skill', {
        skillPath,
        auditVersion: '2.0.0',
        auditEvidence: 'second enrolment',
        allowedResources: []
      }),
      /already exists/i
    );

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'QUARANTINED'
    );
  });

  it('requires explicit re-audit evidence to restore trust', () => {
    const registry = new TrustRegistry(registryPath);

    registry.enrolSkill('test-skill', {
      skillPath,
      auditVersion: '2.0.0',
      auditEvidence: 'initial audit',
      allowedResources: []
    });

    registry.quarantineSkill('test-skill', 'Test quarantine');

    assert.throws(
      () => registry.approveReaudit('test-skill', {
        skillPath,
        allowedResources: [],
        auditVersion: '2.0.0',
        auditEvidence: '',
        operatorApproval: ''
      }),
      /non-empty string/i
    );

    registry.approveReaudit('test-skill', {
      skillPath,
      allowedResources: [],
      auditVersion: '2.0.0',
      auditEvidence: 'reaudit-report-001',
      operatorApproval: 'operator-change-001'
    });

    const reloaded = new TrustRegistry(registryPath);
    assert.equal(
      reloaded.getSkill('test-skill').state,
      'TRUSTED'
    );
  });
});
