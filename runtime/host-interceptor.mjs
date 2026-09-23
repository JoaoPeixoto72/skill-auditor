/**
 * Mandatory Host Interceptor and Network Governor.
 *
 * PRIVILEGED SECURITY BOUNDARY:
 * 1. Blocks direct network access for skills.
 * 2. Routes WebFetch, browser navigation, MCP, and shell commands through Runtime Gate.
 * 3. Immediately revokes network capabilities upon quarantine or violation.
 */

import { executeRuntimeGate, canonicalizeRuntimeUrl } from './runtime-gate.mjs';
import { TrustRegistry, DEFAULT_REGISTRY_PATH } from './trust-registry.mjs';

export class HostNetworkGovernor {
  constructor(registryPath = DEFAULT_REGISTRY_PATH) {
    this.registryPath = registryPath;
    this.revokedSkills = new Map();
    this.activeAudits = new Set();
  }

  isRevoked(skillName) {
    return this.revokedSkills.has(skillName);
  }

  getRevocationReason(skillName) {
    return this.revokedSkills.get(skillName) || null;
  }

  revokeNetworkAccess(skillName, reason) {
    const timestamp = new Date().toISOString();
    this.revokedSkills.set(skillName, {
      reason,
      timestamp
    });

    // Also update trust registry quarantine state
    try {
      const registry = new TrustRegistry(this.registryPath);
      const skill = registry.getSkill(skillName);
      if (!skill || skill.state !== 'QUARANTINED') {
        registry.quarantineSkill(skillName, reason);
      }
    } catch {
      // Ignore registry disk errors during fast-path revocation
    }

    return {
      skillName,
      networkRevoked: true,
      reason,
      timestamp
    };
  }

  restoreNetworkAccess(skillName) {
    this.revokedSkills.delete(skillName);
  }

  /**
   * Mediate WebFetch calls through the Runtime Gate.
   */
  async mediateWebFetch({
    skillName,
    url,
    options = {},
    mockBody = undefined,
    mockSignature = undefined,
    fetchImpl = globalThis.fetch
  }) {
    if (this.isRevoked(skillName)) {
      const revocation = this.getRevocationReason(skillName);
      return {
        allowed: false,
        code: 'NETWORK_REVOKED',
        quarantined: true,
        error: `[HostInterceptor:REVOKED] Network access revoked for ${skillName}: ${revocation.reason}`
      };
    }

    const gateResult = await executeRuntimeGate({
      skillName,
      url,
      registryPath: this.registryPath,
      mockBody,
      mockSignature,
      fetchImpl,
      onQuarantine: (name, reason) => {
        this.revokeNetworkAccess(name, reason);
      }
    });

    if (!gateResult.allowed) {
      if (gateResult.quarantined) {
        this.revokeNetworkAccess(skillName, gateResult.error);
      }
      return gateResult;
    }

    return gateResult;
  }

  /**
   * Mediate browser navigation through the Runtime Gate.
   */
  async mediateBrowserNavigate({ skillName, url }) {
    if (this.isRevoked(skillName)) {
      return {
        allowed: false,
        code: 'NETWORK_REVOKED',
        error: `Browser navigation blocked: Network access is revoked for ${skillName}`
      };
    }

    let canonical;
    try {
      canonical = canonicalizeRuntimeUrl(url);
    } catch (err) {
      this.revokeNetworkAccess(skillName, `Malformed browser navigation URL: ${err.message}`);
      return {
        allowed: false,
        code: 'INVALID_URL',
        error: err.message
      };
    }

    const registry = new TrustRegistry(this.registryPath);
    const skill = registry.getSkill(skillName);

    if (!skill || skill.state === 'QUARANTINED') {
      this.revokeNetworkAccess(skillName, `Unregistered or quarantined skill navigating browser: ${skillName}`);
      return {
        allowed: false,
        code: 'QUARANTINED',
        error: `Skill ${skillName} is not authorized for browser navigation`
      };
    }

    const authorized = skill.allowedResources.some(r => r.url === canonical);
    if (!authorized) {
      const reason = `Browser navigation to unauthorized external URL: ${canonical}`;
      this.revokeNetworkAccess(skillName, reason);
      return {
        allowed: false,
        code: 'UNAUTHORIZED_URL',
        error: reason
      };
    }

    return {
      allowed: true,
      canonicalUrl: canonical
    };
  }

  /**
   * Inspect and mediate shell command execution to block undeclared direct network access.
   */
  mediateShellCommand({ skillName, command }) {
    if (this.isRevoked(skillName)) {
      return {
        allowed: false,
        code: 'NETWORK_REVOKED',
        error: `Shell command execution blocked: Network access revoked for ${skillName}`
      };
    }

    if (typeof command !== 'string') {
      return {
        allowed: false,
        code: 'INVALID_COMMAND',
        error: 'Command must be a string'
      };
    }

    // Prohibited direct network tools in shell
    const NETWORK_TOOL_PATTERNS = [
      /\bcurl\b/i,
      /\bwget\b/i,
      /\b(nc|ncat|netcat)\b/i,
      /\b(ssh|scp|sftp)\b/i,
      /\b(telnet|ftp|tftp)\b/i,
      /\b(invoke-webrequest|invoke-restmethod|iwr|irm)\b/i,
      /\bpython(\d(\.\d+)?)?\s+(-m\s+(http\.server|urllib|requests)|-c\s+.*(urllib|requests|socket|http\.client))/i,
      /\bnode\s+(-e\s+.*(fetch|http|https|net|dgram))/i,
    ];

    for (const pattern of NETWORK_TOOL_PATTERNS) {
      if (pattern.test(command)) {
        const reason = `Direct outbound network tool prohibited in shell command: pattern ${pattern.source}`;
        this.revokeNetworkAccess(skillName, reason);
        return {
          allowed: false,
          code: 'UNMEDIATED_NETWORK_BLOCKED',
          quarantined: true,
          error: `[HostInterceptor:SECURITY_VIOLATION] ${reason}`
        };
      }
    }

    return {
      allowed: true
    };
  }

  /**
   * Mediate Model Context Protocol (MCP) tool requests.
   */
  async mediateMcpRequest({
    skillName,
    mcpServer,
    toolName,
    args = {}
  }) {
    if (this.isRevoked(skillName)) {
      return {
        allowed: false,
        code: 'NETWORK_REVOKED',
        error: `MCP call blocked: Network access revoked for ${skillName}`
      };
    }

    // Detect network-bearing MCP calls (e.g. fetch, download, navigate, browse, request)
    const isNetworkTool = /^(fetch|download|browse|navigate|request|http_get|http_post)$/i.test(toolName);
    const targetUrl = args.url || args.uri || args.href || null;

    if (isNetworkTool && targetUrl) {
      return await this.mediateWebFetch({
        skillName,
        url: targetUrl
      });
    }

    // Default MCP allowed if not an unmediated network call
    return {
      allowed: true
    };
  }

  /**
   * Return a gated fetch implementation scoped to a specific skill.
   */
  createGatedFetch(skillName, fetchImpl = globalThis.fetch) {
    return async (input, init = {}) => {
      const url = typeof input === 'string' ? input : input?.url || String(input);
      const res = await this.mediateWebFetch({
        skillName,
        url,
        options: init,
        fetchImpl
      });

      if (!res.allowed) {
        throw new Error(res.error || `[HostInterceptor:BLOCKED] Access to ${url} denied`);
      }

      if (res.tier === 1 || res.tier === 3) {
        return new Response(res.content, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' }
        });
      }

      if (res.tier === 2) {
        return new Response(JSON.stringify(res.envelope), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      throw new Error(`Unhandled tier response: ${res.tier}`);
    };
  }
}
