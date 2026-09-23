#!/usr/bin/env node

/**
 * Privileged Runtime Gate.
 *
 * SECURITY BOUNDARY:
 * This module runs in the privileged host process.
 * Skills cannot write to the trust registry, make untrusted network requests,
 * or bypass this gate.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import {
  DEFAULT_REGISTRY_PATH,
  TrustRegistry,
  calculateBundleHash
} from './trust-registry.mjs';

function now() {
  return new Date().toISOString();
}

function assertNonEmptyString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${name} must be a non-empty string`);
  }
}

function isPrivateIpv4(hostname) {
  const parts = hostname.split('.').map(Number);
  if (
    parts.length !== 4 ||
    parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 0
  );
}

function isPrivateLiteral(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (normalized === 'localhost' || normalized.endsWith('.localhost')) {
    return true;
  }

  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) {
    return isPrivateIpv4(normalized);
  }
  if (ipVersion === 6) {
    return (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb')
    );
  }
  return false;
}

export function canonicalizeRuntimeUrl(value) {
  assertNonEmptyString(value, 'url');

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`Invalid URL: ${value}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS runtime URLs are permitted');
  }

  if (parsed.username || parsed.password) {
    throw new Error('Credentials embedded in URLs are forbidden');
  }

  if (isPrivateLiteral(parsed.hostname)) {
    throw new Error('Loopback and private-address literals are forbidden');
  }

  parsed.hash = '';
  return parsed.href;
}

export function validateTier2Payload(payload, schema) {
  if (
    payload === null ||
    typeof payload !== 'object' ||
    Array.isArray(payload)
  ) {
    return {
      valid: false,
      reason: 'Tier 2 payload is not a JSON object'
    };
  }

  const keys = Object.keys(payload);
  const allowed = new Set(schema.allowedKeys);
  const required = new Set(schema.requiredKeys || []);

  const unexpected = keys.filter(key => !allowed.has(key));
  const missing = [...required].filter(key => !(key in payload));

  if (unexpected.length > 0) {
    return {
      valid: false,
      reason: `Unexpected keys in Tier 2 payload: ${unexpected.join(', ')}`
    };
  }

  if (missing.length > 0) {
    return {
      valid: false,
      reason: `Missing required keys in Tier 2 payload: ${missing.join(', ')}`
    };
  }

  return { valid: true };
}

async function readResponseBytes(response, maxBytes) {
  if (!response.body || typeof response.body.getReader !== 'function') {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maxBytes) {
      throw new Error(`Response exceeds ${maxBytes} bytes`);
    }
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`Response exceeds ${maxBytes} bytes`);
    }
    chunks.push(Buffer.from(value));
  }

  return Buffer.concat(chunks, total);
}

function resultBlocked(code, reason, quarantined = false) {
  return {
    allowed: false,
    code,
    quarantined,
    error: `[RuntimeGate:BLOCKED] ${reason}`
  };
}

export async function executeRuntimeGate({
  skillName,
  url,
  registryPath = DEFAULT_REGISTRY_PATH,
  mockBody = undefined,
  mockSignature = undefined,
  fetchImpl = globalThis.fetch,
  onQuarantine = null
}) {
  const registry = new TrustRegistry(registryPath);
  const skill = registry.getSkill(skillName);

  const notifyQuarantine = (reason) => {
    registry.quarantineSkill(skillName, reason);
    if (typeof onQuarantine === 'function') {
      try {
        onQuarantine(skillName, reason);
      } catch {
        // preserve quarantine logic
      }
    }
  };

  if (!skill) {
    const reason = `Skill '${skillName}' is not registered in Trust Registry`;
    notifyQuarantine(reason);
    return resultBlocked('UNREGISTERED_SKILL', reason, true);
  }

  if (skill.state === 'QUARANTINED') {
    return resultBlocked(
      'QUARANTINED',
      `Skill '${skillName}' is quarantined: ${skill.quarantineReason || 'security violation'}`,
      true
    );
  }

  let normalizedUrl;
  try {
    normalizedUrl = canonicalizeRuntimeUrl(url);
  } catch (error) {
    notifyQuarantine(error.message);
    return resultBlocked('INVALID_URL', error.message, true);
  }

  const resource = skill.allowedResources.find(
    candidate => candidate.url === normalizedUrl
  );

  if (!resource) {
    const reason = `Unauthorized external URL: ${normalizedUrl}`;
    notifyQuarantine(reason);
    return resultBlocked('UNAUTHORIZED_URL', reason, true);
  }

  let currentBundleHash;
  try {
    currentBundleHash = calculateBundleHash(skill.skillPath);
  } catch (error) {
    const reason = `Unable to verify installed skill bundle: ${error.message}`;
    notifyQuarantine(reason);
    return resultBlocked('BUNDLE_VERIFICATION_FAILED', reason, true);
  }

  if (currentBundleHash !== skill.bundleHash) {
    const reason =
      `Local skill bundle changed after audit. Expected ${skill.bundleHash}, ` +
      `got ${currentBundleHash}`;
    notifyQuarantine(reason);
    return resultBlocked('LOCAL_BUNDLE_HASH_MISMATCH', reason, true);
  }

  if (resource.tier === 0) {
    const reason =
      `Programmatic fetch of Tier 0 human-only documentation is forbidden: ${normalizedUrl}`;
    notifyQuarantine(reason);
    return resultBlocked('TIER0_FETCH_PROHIBITED', reason, true);
  }

  let bytes;
  let detachedSignature = mockSignature;

  if (mockBody !== undefined) {
    if (Buffer.isBuffer(mockBody)) {
      bytes = mockBody;
    } else if (mockBody instanceof Uint8Array) {
      bytes = Buffer.from(mockBody);
    } else if (typeof mockBody === 'string') {
      bytes = Buffer.from(mockBody, 'utf8');
    } else {
      bytes = Buffer.from(JSON.stringify(mockBody), 'utf8');
    }

    if (bytes.length > resource.maxBytes) {
      return resultBlocked(
        'RESPONSE_TOO_LARGE',
        `Response exceeds ${resource.maxBytes} bytes`
      );
    }
  } else {
    if (typeof fetchImpl !== 'function') {
      return resultBlocked(
        'FETCH_UNAVAILABLE',
        'The privileged host did not provide a fetch implementation'
      );
    }

    let response;
    try {
      response = await fetchImpl(normalizedUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          accept: resource.tier === 2
            ? 'application/json'
            : 'application/octet-stream'
        }
      });
    } catch (error) {
      return resultBlocked(
        'NETWORK_EXCEPTION',
        `Network request failed: ${error.message}`
      );
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location') || 'unknown';
      const reason =
        `Redirect blocked. Destination must be separately declared: ${location}`;
      notifyQuarantine(reason);
      return resultBlocked('REDIRECT_BLOCKED', reason, true);
    }

    if (!response.ok) {
      return resultBlocked(
        'NETWORK_ERROR',
        `Remote server returned HTTP ${response.status}`
      );
    }

    detachedSignature =
      detachedSignature ||
      response.headers.get('x-content-signature') ||
      undefined;

    try {
      bytes = await readResponseBytes(response, resource.maxBytes);
    } catch (error) {
      return resultBlocked('RESPONSE_TOO_LARGE', error.message);
    }
  }

  // TIER 1: Pinned byte-for-byte SHA256
  if (resource.tier === 1) {
    const computed = crypto
      .createHash('sha256')
      .update(bytes)
      .digest('hex');

    const expected = resource.hash.slice('sha256-'.length).toLowerCase();

    if (computed !== expected) {
      const reason =
        `Remote resource hash mismatch for ${normalizedUrl}. ` +
        `Expected sha256-${expected}, got sha256-${computed}`;
      notifyQuarantine(reason);

      return {
        ...resultBlocked('RUG_PULL_HASH_MISMATCH', reason, true),
        expectedHash: expected,
        computedHash: computed
      };
    }

    return {
      allowed: true,
      tier: 1,
      content: bytes,
      hashVerified: true,
      hash: computed
    };
  }

  // TIER 2: Constrained structured JSON data feed
  if (resource.tier === 2) {
    let payload;
    try {
      payload = JSON.parse(bytes.toString('utf8'));
    } catch {
      return resultBlocked(
        'TIER2_INVALID_JSON',
        'Tier 2 response is not valid JSON'
      );
    }

    const validation = validateTier2Payload(payload, resource.schema);
    if (!validation.valid) {
      return resultBlocked('TIER2_SCHEMA_REJECTED', validation.reason);
    }

    return {
      allowed: true,
      tier: 2,
      envelope: {
        type: 'data_feed_envelope',
        source: normalizedUrl,
        fetchedAt: now(),
        payload,
        isExecutableInstruction: false,
        instructionChannelEligible: false
      }
    };
  }

  // TIER 3: Cryptographically signed payload with Ed25519
  if (resource.tier === 3) {
    const trustedKey = registry.data.trustedKeys[resource.keyId];
    if (!trustedKey) {
      const reason = `Unknown trusted key: ${resource.keyId}`;
      notifyQuarantine(reason);
      return resultBlocked('TIER3_UNKNOWN_KEY', reason, true);
    }

    if (
      typeof detachedSignature !== 'string' ||
      detachedSignature.trim() === ''
    ) {
      const reason = 'Tier 3 payload has no detached Ed25519 signature';
      notifyQuarantine(reason);
      return resultBlocked('TIER3_UNSIGNED', reason, true);
    }

    let signature;
    try {
      signature = Buffer.from(detachedSignature, 'base64');
      if (signature.length === 0) {
        throw new Error('empty signature');
      }
    } catch (error) {
      const reason = `Invalid Tier 3 signature encoding: ${error.message}`;
      notifyQuarantine(reason);
      return resultBlocked('TIER3_INVALID_SIGNATURE_ENCODING', reason, true);
    }

    let verified = false;
    try {
      verified = crypto.verify(
        null,
        bytes,
        trustedKey.publicKeyPem,
        signature
      );
    } catch (error) {
      const reason = `Tier 3 signature verification failed: ${error.message}`;
      notifyQuarantine(reason);
      return resultBlocked('TIER3_SIGNATURE_ERROR', reason, true);
    }

    if (!verified) {
      const reason = 'Tier 3 Ed25519 signature is invalid';
      notifyQuarantine(reason);
      return resultBlocked('TIER3_SIGNATURE_INVALID', reason, true);
    }

    return {
      allowed: true,
      tier: 3,
      content: bytes,
      signatureVerified: true,
      keyId: resource.keyId
    };
  }

  const reason = `Unknown resource tier: ${resource.tier}`;
  notifyQuarantine(reason);
  return resultBlocked('UNKNOWN_TIER', reason, true);
}
