// api/scripts/loader.js
// ============================================
// SECURE SCRIPT DELIVERY ENGINE
// ============================================
// This is the core endpoint that Roblox executors call

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const CryptoEngine = require('../../lib/crypto');
const RateLimiter = require('../security/ratelimit');
const IPGuard = require('../security/ipguard');
const AntiBypass = require('../security/antibypass');
const Fingerprint = require('../security/fingerprint');
const Obfuscator = require('./obfuscate');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  if (req.method !== 'POST') return Utils.error(res, 405, 'Method not allowed');
  
  const startTime = Date.now();
  const ip = Utils.getIP(req);
  const requestId = Utils.generateRequestId();
  
  try {
    // ══════════════════════════════════════
    // SECURITY PIPELINE
    // ══════════════════════════════════════
    
    // 1. Rate limit (strict for loader)
    const rateLimit = RateLimiter.checkLoader(ip);
    RateLimiter.applyHeaders(res, rateLimit);
    if (!rateLimit.allowed) {
      Database.recordEvent({ type: 'loader_rate_limited', ip });
      return Utils.error(res, 429, 'Rate limited', 'RATE_LIMITED');
    }
    
    // 2. IP guard
    const ipCheck = IPGuard.validate(ip);
    if (!ipCheck.valid) {
      return Utils.error(res, 403, ipCheck.reason, ipCheck.code);
    }
    
    // 3. Anti-bypass
    const body = await Utils.parseBody(req);
    const bypassCheck = AntiBypass.validateRequest(req, body);
    if (!bypassCheck.valid && bypassCheck.score < 50) {
      Database.recordFailedAttempt(ip);
      IPGuard.checkAndAutoBlacklist(ip);
      return Utils.error(res, 403, 'Security check failed', 'BYPASS_DETECTED');
    }
    
    // ══════════════════════════════════════
    // SESSION VALIDATION
    // ══════════════════════════════════════
    
    const { sessionToken, scriptId, projectId } = body;
    
    if (!sessionToken) {
      return Utils.error(res, 401, 'Session token required. Authenticate first.', 'NO_SESSION');
    }
    
    // Validate session
    const session = Database.getSession(sessionToken);
    if (!session) {
      return Utils.error(res, 401, 'Invalid or expired session', 'SESSION_INVALID');
    }
    
    // Verify fingerprint
    const currentFP = Fingerprint.generate(req);
    if (!Fingerprint.compare(session.fingerprint, currentFP)) {
      Database.deleteSession(sessionToken);
      Database.recordEvent({
        type: 'loader_fingerprint_mismatch',
        keyId: session.keyId,
        ip,
      });
      return Utils.error(res, 401, 'Session integrity check failed', 'FINGERPRINT_MISMATCH');
    }
    
    // ══════════════════════════════════════
    // KEY VERIFICATION
    // ══════════════════════════════════════
    
    const keyRecord = Database.getKey(session.keyId);
    if (!keyRecord || keyRecord.status !== 'active') {
      Database.deleteSession(sessionToken);
      return Utils.error(res, 403, 'Associated key is no longer valid', 'KEY_INVALID');
    }
    
    // ══════════════════════════════════════
    // SCRIPT RETRIEVAL & DECRYPTION
    // ══════════════════════════════════════
    
    const masterKey = process.env.MASTER_KEY;
    if (!masterKey) {
      return Utils.error(res, 500, 'Server configuration error', 'CONFIG_ERROR');
    }
    
    // Find the right script
    let targetScriptId = scriptId;
    
    if (!targetScriptId && projectId) {
      const project = Database.getProject(projectId);
      if (project && project.scriptId) {
        targetScriptId = project.scriptId;
      }
    }
    
    if (!targetScriptId) {
      // Get default/first script
      const allScripts = Database.getAllScripts(projectId);
      if (allScripts.length > 0) {
        targetScriptId = allScripts[0].id;
      }
    }
    
    if (!targetScriptId) {
      return Utils.error(res, 404, 'No script found', 'SCRIPT_NOT_FOUND');
    }
    
    // Decrypt script (AES-256-GCM)
    const decryptedSource = Database.decryptScript(targetScriptId, masterKey);
    if (!decryptedSource) {
      return Utils.error(res, 500, 'Script decryption failed', 'DECRYPT_ERROR');
    }
    
    // ══════════════════════════════════════
    // OBFUSCATION & PROTECTION
    // ══════════════════════════════════════
    
    const obfuscated = Obfuscator.obfuscate(decryptedSource, {
      layers: 3,
      sessionToken,
      expiresAt: session.expiresAt,
    });
    
    // ══════════════════════════════════════
    // RUNTIME ENCRYPTION (for transport)
    // ══════════════════════════════════════
    
    // Generate a one-time transport key
    const transportKey = CryptoEngine.generateSessionToken().substring(0, 32);
    const encryptedPayload = CryptoEngine.encrypt(obfuscated.source, transportKey);
    
    // Update session
    Database.updateSession(sessionToken, {
      requestCount: session.requestCount + 1,
    });
    
    // Record event
    const loadTime = Date.now() - startTime;
    Database.recordEvent({
      type: 'script_loaded',
      keyId: session.keyId,
      ip,
      data: {
        scriptId: targetScriptId,
        loadTimeMs: loadTime,
        obfuscationLayers: obfuscated.layers.length,
      }
    });
    
    // ══════════════════════════════════════
    // DELIVERY
    // ══════════════════════════════════════
    
    // Set performance headers
    res.setHeader('X-Load-Time', `${loadTime}ms`);
    res.setHeader('X-Request-Id', requestId);
    res.setHeader('X-Script-Version', Database.getScript(targetScriptId)?.version || '1.0.0');
    
    return Utils.success(res, {
      // The script payload
      payload: {
        encrypted: encryptedPayload,
        transportKey,
        // Or deliver directly for simpler setups:
        script: obfuscated.source,
      },
      meta: {
        version: Database.getScript(targetScriptId)?.version,
        loadTimeMs: loadTime,
        expiresAt: session.expiresAt,
        layers: obfuscated.layers,
      },
      requestId,
    }, 'Script delivered');
    
  } catch (err) {
    Database.recordEvent({ type: 'loader_error', ip, data: { error: err.message } });
    return Utils.error(res, 500, 'Script delivery failed', 'DELIVERY_ERROR');
  }
};
