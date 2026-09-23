/**
 * Trust Registry for Agent Skills.
 *
 * PRIVILEGED COMPONENT:
 * Manages trusted skill bundle hashes, allowed external resources, public signing keys,
 * and quarantine status in a local atomic JSON database.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const DEFAULT_REGISTRY_PATH = path.resolve(
  process.cwd(),
  '.audit',
  'trust-registry.json'
);

const VALID_STATES = new Set(['TRUSTED', 'QUARANTINED']);
const VALID_TIERS = new Set([0, 1, 2, 3]);
const MAX_ALLOWED_BYTES = 10 * 1024 * 1024; // 10 MiB

function now() {
  return new Date().toISOString();
}

function assertNonEmptyString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${name} must be a non-empty string`);
  }
}

function validateHash(value) {
  return (
    typeof value === 'string' &&
    /^sha256-[a-fA-F0-9]{64}$/.test(value)
  );
}

function validateTier2Schema(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    return false;
  }
  if (schema.type !== 'object' || !Array.isArray(schema.allowedKeys)) {
    return false;
  }
  if (schema.requiredKeys !== undefined && !Array.isArray(schema.requiredKeys)) {
    return false;
  }
  return (
    schema.allowedKeys.every(k => typeof k === 'string') &&
    (schema.requiredKeys || []).every(k => typeof k === 'string')
  );
}

export function normalizeResource(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) {
    throw new Error('Resource must be an object');
  }

  assertNonEmptyString(resource.url, 'resource.url');
  const tier = resource.tier;
  const maxBytes = resource.maxBytes;

  if (!VALID_TIERS.has(tier)) {
    throw new Error(`Unknown resource tier: ${tier}`);
  }

  if (
    !Number.isInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > MAX_ALLOWED_BYTES
  ) {
    throw new Error(`maxBytes must be between 1 and ${MAX_ALLOWED_BYTES}`);
  }

  assertNonEmptyString(resource.purpose, 'resource.purpose');

  const normalized = {
    url: resource.url.trim(),
    tier,
    purpose: resource.purpose.trim(),
    maxBytes
  };

  if (tier === 1) {
    if (!validateHash(resource.hash)) {
      throw new Error(`Tier 1 resource ${resource.url} needs a valid sha256-<hex> hash pin`);
    }
    normalized.hash = resource.hash.toLowerCase();
  }

  if (tier === 2) {
    if (!validateTier2Schema(resource.schema)) {
      throw new Error(`Tier 2 resource ${resource.url} needs a valid object schema`);
    }
    normalized.schema = {
      type: 'object',
      allowedKeys: [...new Set(resource.schema.allowedKeys)],
      requiredKeys: [...new Set(resource.schema.requiredKeys || [])]
    };
  }

  if (tier === 3) {
    assertNonEmptyString(resource.keyId, 'resource.keyId');
    normalized.keyId = resource.keyId.trim();
  }

  return normalized;
}

export function validateRegistryData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Trust Registry is not an object');
  }

  if (data.version !== '2.0.0') {
    throw new Error(`Unsupported Trust Registry version: ${data.version}`);
  }

  if (!data.skills || typeof data.skills !== 'object' || Array.isArray(data.skills)) {
    throw new Error('Trust Registry skills field is invalid');
  }

  if (!data.trustedKeys || typeof data.trustedKeys !== 'object' || Array.isArray(data.trustedKeys)) {
    throw new Error('Trust Registry trustedKeys field is invalid');
  }

  for (const [name, skill] of Object.entries(data.skills)) {
    assertNonEmptyString(name, 'skill name');
    if (!skill || typeof skill !== 'object') {
      throw new Error(`Invalid skill registry entry: ${name}`);
    }
    if (!VALID_STATES.has(skill.state)) {
      throw new Error(`Invalid state for ${name}: ${skill.state}`);
    }
    if (!/^[a-f0-9]{64}$/.test(skill.bundleHash || '')) {
      throw new Error(`Invalid bundle hash for ${name}`);
    }
    if (!Array.isArray(skill.allowedResources)) {
      throw new Error(`Invalid resource list for ${name}`);
    }
    skill.allowedResources = skill.allowedResources.map(normalizeResource);
  }

  return data;
}

function shouldExcludeBundlePath(relativePath) {
  const parts = relativePath.split('/');
  return parts.some(part =>
    ['.git', '.audit', 'node_modules', 'dist', 'build', '.coverage', '__pycache__'].includes(part)
  );
}

export function listBundleFiles(root) {
  const output = [];

  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');

      if (shouldExcludeBundlePath(relative)) {
        continue;
      }

      if (entry.isSymbolicLink()) {
        throw new Error(`Symbolic links are not allowed in skill bundles: ${relative}`);
      }

      if (entry.isDirectory()) {
        walk(absolute);
      } else if (entry.isFile()) {
        output.push({ absolute, relative });
      }
    }
  }

  walk(root);
  return output;
}

export function calculateBundleHash(skillPath) {
  assertNonEmptyString(skillPath, 'skillPath');

  const root = path.resolve(skillPath);
  if (!fs.existsSync(root)) {
    throw new Error(`skillPath does not exist: ${skillPath}`);
  }
  const statResult = fs.statSync(root);

  if (!statResult.isDirectory()) {
    throw new Error('skillPath must be a directory');
  }

  const digest = crypto.createHash('sha256');

  for (const file of listBundleFiles(root)) {
    const bytes = fs.readFileSync(file.absolute);
    const relativeBytes = Buffer.from(file.relative, 'utf8');
    const lengthBytes = Buffer.from(String(bytes.length), 'ascii');

    digest.update(relativeBytes);
    digest.update(Buffer.from([0]));
    digest.update(lengthBytes);
    digest.update(Buffer.from([0]));
    digest.update(bytes);
    digest.update(Buffer.from([0]));
  }

  return digest.digest('hex');
}

export class TrustRegistry {
  constructor(registryPath = DEFAULT_REGISTRY_PATH) {
    this.registryPath = path.resolve(registryPath);
    this.data = this.load();
  }

  emptyRegistry() {
    return {
      version: '2.0.0',
      trustedKeys: {},
      skills: {}
    };
  }

  load() {
    if (!fs.existsSync(this.registryPath)) {
      return this.emptyRegistry();
    }

    try {
      const raw = fs.readFileSync(this.registryPath, 'utf8');
      const parsed = JSON.parse(raw);
      return validateRegistryData(parsed);
    } catch (err) {
      throw new Error(`Failed to load Trust Registry at ${this.registryPath}: ${err.message}`);
    }
  }

  save() {
    validateRegistryData(this.data);

    const directory = path.dirname(this.registryPath);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

    const temporary = `${this.registryPath}.${process.pid}.${crypto.randomUUID()}.tmp`;

    try {
      fs.writeFileSync(
        temporary,
        `${JSON.stringify(this.data, null, 2)}\n`,
        {
          encoding: 'utf8',
          mode: 0o600,
          flag: 'wx'
        }
      );

      fs.renameSync(temporary, this.registryPath);

      if (process.platform !== 'win32') {
        try {
          fs.chmodSync(this.registryPath, 0o600);
        } catch {
          // ignore chmod errors on systems that do not support it
        }
      }
    } catch (error) {
      try {
        if (fs.existsSync(temporary)) {
          fs.unlinkSync(temporary);
        }
      } catch {
        // Preserve the original failure.
      }
      throw new Error(`Failed to persist Trust Registry: ${error.message}`);
    }
  }

  reload() {
    this.data = this.load();
    return this.data;
  }

  getSkill(skillName) {
    return this.data.skills[skillName] || null;
  }

  listSkills() {
    return Object.values(this.data.skills);
  }

  isSkillTrusted(skillName) {
    const skill = this.getSkill(skillName);
    return skill !== null && skill.state === 'TRUSTED';
  }

  addTrustedKey(keyId, publicKeyPem, metadata = {}) {
    assertNonEmptyString(keyId, 'keyId');
    assertNonEmptyString(publicKeyPem, 'publicKeyPem');

    const key = crypto.createPublicKey(publicKeyPem);

    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('Trusted key must be an Ed25519 public key');
    }

    this.data.trustedKeys[keyId] = {
      keyId,
      publicKeyPem,
      addedAt: now(),
      metadata
    };

    this.save();
    return this.data.trustedKeys[keyId];
  }

  enrolSkill(skillName, {
    skillPath,
    allowedResources = [],
    auditVersion = '1.0.0',
    auditEvidence = ''
  }) {
    assertNonEmptyString(skillName, 'skillName');
    assertNonEmptyString(skillPath, 'skillPath');

    if (this.data.skills[skillName]) {
      throw new Error(
        `Skill '${skillName}' already exists. Ordinary enrolment cannot overwrite it.`
      );
    }

    const resources = allowedResources.map(normalizeResource);

    for (const resource of resources) {
      if (resource.tier === 3 && !this.data.trustedKeys[resource.keyId]) {
        throw new Error(
          `Tier 3 resource references unknown trusted key '${resource.keyId}'`
        );
      }
    }

    const bundleHash = calculateBundleHash(skillPath);
    const timestamp = now();

    this.data.skills[skillName] = {
      name: skillName,
      state: 'TRUSTED',
      skillPath: path.resolve(skillPath),
      bundleHash,
      allowedResources: resources,
      registeredAt: timestamp,
      updatedAt: timestamp,
      auditedAt: timestamp,
      auditVersion,
      auditEvidence,
      quarantineReason: null
    };

    this.save();
    return this.data.skills[skillName];
  }

  quarantineSkill(skillName, reason) {
    assertNonEmptyString(skillName, 'skillName');
    assertNonEmptyString(reason, 'reason');

    const existing = this.data.skills[skillName];
    const timestamp = now();

    if (!existing) {
      this.data.skills[skillName] = {
        name: skillName,
        state: 'QUARANTINED',
        skillPath: '',
        bundleHash: '0'.repeat(64),
        allowedResources: [],
        registeredAt: timestamp,
        updatedAt: timestamp,
        auditedAt: null,
        auditVersion: null,
        auditEvidence: null,
        quarantineReason: reason
      };
    } else {
      existing.state = 'QUARANTINED';
      existing.updatedAt = timestamp;
      existing.quarantineReason = reason;
    }

    this.save();
    return this.data.skills[skillName];
  }

  approveReaudit(skillName, {
    skillPath,
    allowedResources = [],
    auditVersion,
    auditEvidence,
    operatorApproval
  }) {
    const existing = this.data.skills[skillName];

    if (!existing) {
      throw new Error(`Skill '${skillName}' is not registered`);
    }

    if (existing.state !== 'QUARANTINED') {
      throw new Error('Re-audit approval is only valid for quarantined skills');
    }

    assertNonEmptyString(operatorApproval, 'operatorApproval');
    assertNonEmptyString(auditVersion, 'auditVersion');
    assertNonEmptyString(auditEvidence, 'auditEvidence');

    const resources = allowedResources.map(normalizeResource);

    for (const resource of resources) {
      if (resource.tier === 3 && !this.data.trustedKeys[resource.keyId]) {
        throw new Error(
          `Tier 3 resource references unknown trusted key '${resource.keyId}'`
        );
      }
    }

    existing.skillPath = path.resolve(skillPath);
    existing.bundleHash = calculateBundleHash(skillPath);
    existing.allowedResources = resources;
    existing.state = 'TRUSTED';
    existing.updatedAt = now();
    existing.auditedAt = now();
    existing.auditVersion = auditVersion;
    existing.auditEvidence = auditEvidence;
    existing.operatorApproval = operatorApproval;
    existing.quarantineReason = null;

    this.save();
    return existing;
  }
}
