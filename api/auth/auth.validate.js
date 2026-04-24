// api/auth/validate.js
// ============================================
// KEY VALIDATION ENGINE
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const CryptoEngine = require('../../lib/crypto');
const RateLimiter = require('../security/ratelimit');
const IPGuard = require('../security/ipguard');
const AntiBypass = require('../security/antibypass');
const Fingerprint = require('../security/fingerprint');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  if (req.method !== 'POST') return Utils.error(res, 405, 'Method not allowed', 'METHOD_NOT_ALLOWED');
  
  const ip = Utils.getIP(req);
  const requestId = Utils.generateRequestId();
  
  try {
    // ── Step 1: Rate Limit Check ──
    const rateLimit = RateLimiter.checkAuth(ip);
    RateLimiter.applyHeaders(res, rateLimit);
    
    if (!rateLimit.allowed) {
      Database.recordEvent({ type: 'rate_limited', ip, data: { endpoint: 'validate' } });
      return Utils.error(res, 429, 'Too many attempts. Try again later.', 'RATE_LIMITED');
    }
    
    // ── Step 2: IP Validation ──
    const ipCheck = IPGuard.validate(ip);
    if (!ipCheck.valid) {
      Database.recordEvent({ type: 'ip_blocked', ip, data: { reason: ipCheck.reason } });
      return Utils.error(res, 403, ipCheck.reason, ipCheck.code);
    }
    
    // ── Step 3: Anti-Bypass Check ──
    const body = await Utils.parseBody(req);
    const bypassCheck = AntiBypass.validateRequest(req, body);
    
    if (!bypassCheck.valid && bypassCheck.score < 50) {
      Database.recordEvent({ type: 'bypass_attempt', ip, data: bypassCheck });
      Database.recordFailedAttempt(ip);
      IPGuard.checkAndAutoBlacklist(ip);
      return Utils.error(res, 403, 'Request validation failed', 'BYPASS_DETECTED');
    }
    
    // ── Step 4: Parse & Validate Input ──
    const { key, hwid } = body;
    
    if (!key) {
      return Utils.error(res, 400, 'License key is required', 'MISSING_KEY');
    }
    
    if (!hwid) {
      return Utils.error(res, 400, 'HWID is required', 'MISSING_HWID');
    }
    
    // ── Step 5: Key Lookup ──
    const keyRecord = Database.getKey(key);
    
    if (!keyRecord) {
      Database.recordFailedAttempt(ip);
      Database.recordEvent({ type: 'invalid_key', ip, data: { key: Utils.maskKey(key) } });
      IPGuard.checkAndAutoBlacklist(ip);
      return Utils.error(res, 401, 'Invalid license key', 'INVALID_KEY');
    }
    
    // ── Step 6: Key Status Check ──
    if (keyRecord.status !== 'active') {
      Database.recordEvent({ 
        type: 'inactive_key_attempt', 
        keyId: keyRecord.id, 
        ip, 
        data: { status: keyRecord.status } 
      });
      
      const statusMessages = {
        suspended: 'License key has been suspended',
        expired: 'License key has expired',
        revoked: 'License key has been revoked',
      };
      
      return Utils.error(res, 403, 
        statusMessages[keyRecord.status] || 'Key is not active', 
        'KEY_INACTIVE'
      );
    }
    
    // ── Step 7: Expiry Check ──
    if (keyRecord.expiresAt && keyRecord.expiresAt < Date.now()) {
      Database.updateKey(keyRecord.id, { status: 'expired' });
      return Utils.error(res, 403, 'License key has expired', 'KEY_EXPIRED');
    }
    
    // ── Step 8: HWID Validation ──
    if (keyRecord.hwid) {
      // HWID already bound - verify match
      if (keyRecord.hwid !== hwid) {
        Database.recordEvent({
          type: 'hwid_mismatch',
          keyId: keyRecord.id,
          ip,
          data: { 
            expected: Utils.maskKey(keyRecord.hwid), 
            received: Utils.maskKey(hwid) 
          }
        });
        Database.recordFailedAttempt(ip);
        return Utils.error(res, 403, 'HWID mismatch. This key is bound to another device.', 'HWID_MISMATCH');
      }
    } else {
      // First use - bind HWID
      Database.updateKey(keyRecord.id, { hwid });
      Database.recordEvent({
        type: 'hwid_bound',
        keyId: keyRecord.id,
        ip,
        data: { hwid: Utils.maskKey(hwid) }
      });
    }
    
    // ── Step 9: IP Whitelist Check (per-key) ──
    if (keyRecord.allowedIPs.length > 0 && !keyRecord.allowedIPs.includes(ip)) {
      return Utils.error(res, 403, 'IP not authorized for this key', 'IP_NOT_AUTHORIZED');
    }
    
    // ── Step 10: Session Management ──
    const existingSessions = Database.getSessionsByKey(keyRecord.id);
    
    if (existingSessions.length >= keyRecord.maxSessions) {
      // Kill oldest session
      const oldest = existingSessions.sort((a, b) => a.createdAt - b.createdAt)[0];
      Database.deleteSession(oldest.token);
    }
    
    // Create new session
    const fingerprint = Fingerprint.generate(req);
    const session = Database.createSession({
      keyId: keyRecord.id,
      ip,
      hwid,
      fingerprint,
      userAgent: req.headers['user-agent'],
      ttl: 300000, // 5 minutes
    });
    
    // ── Step 11: Update Key Stats ──
    Database.updateKey(keyRecord.id, {
      lastUsed: Date.now(),
      totalExecutions: keyRecord.totalExecutions + 1,
    });
    
    // Clear failed attempts on success
    Database.clearFailedAttempts(ip);
    
    // ── Step 12: Record Success ──
    Database.recordEvent({
      type: 'auth_success',
      keyId: keyRecord.id,
      ip,
      data: { 
        hwid: Utils.maskKey(hwid),
        sessionToken: session.token.substring(0, 8) + '...',
      }
    });
    
    // ── Response ──
    return Utils.success(res, {
      session: {
        token: session.token,
        expiresAt: session.expiresAt,
        ttl: 300000,
      },
      key: {
        id: keyRecord.id,
        type: keyRecord.type,
        expiresAt: keyRecord.expiresAt,
        remaining: Utils.timeRemaining(keyRecord.expiresAt),
      },
      requestId,
    }, 'Authentication successful');
    
  } catch (err) {
    Database.recordEvent({ type: 'auth_error', ip, data: { error: err.message } });
    return Utils.error(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  }
};
