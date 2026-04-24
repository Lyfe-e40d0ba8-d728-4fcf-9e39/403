// api/gateway.js
// ============================================
// MAIN API GATEWAY & ROUTER
// ============================================
// Enterprise Script Protection System v2.0
// ============================================

const Database = require('../lib/database');
const CryptoEngine = require('../lib/crypto');
const Utils = require('../lib/utils');
const RateLimiter = require('./security/ratelimit');
const IPGuard = require('./security/ipguard');
const AntiBypass = require('./security/antibypass');
const Fingerprint = require('./security/fingerprint');
const Obfuscator = require('./scripts/obfuscate');

module.exports = async function handler(req, res) {
  const startTime = Date.now();
  
  // ── CORS ──
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') {
    return Utils.success(res, {}, 'OK');
  }
  
  const ip = Utils.getIP(req);
  const requestId = Utils.generateRequestId();
  
  // ══════════════════════════════════════════
  // GLOBAL SECURITY LAYER
  // ══════════════════════════════════════════
  
  // 1. IP Blacklist Check
  if (Database.isBlacklisted(ip)) {
    return Utils.error(res, 403, 'Access denied', 'IP_BLACKLISTED');
  }
  
  // 2. Global Rate Limit
  const globalRL = RateLimiter.checkGeneral(ip);
  RateLimiter.applyHeaders(res, globalRL);
  if (!globalRL.allowed) {
    Database.recordEvent({ type: 'rate_limited', ip, data: { endpoint: 'gateway' } });
    return Utils.error(res, 429, `Rate limited. Retry after ${globalRL.retryAfter}s`, 'RATE_LIMITED');
  }
  
  // ══════════════════════════════════════════
  // ROUTE HANDLING
  // ══════════════════════════════════════════
  
  try {
    const body = req.method === 'POST' ? await Utils.parseBody(req) : {};
    const action = body.action || req.query?.action || 'info';
    
    switch (action) {
      
      // ─────────────────────────────────────
      // INFO / HEALTH CHECK
      // ─────────────────────────────────────
      case 'info':
      case 'health': {
        return Utils.success(res, {
          service: 'Script Protection System',
          version: '2.0.0',
          status: 'operational',
          features: [
            'AES-256-GCM Encryption',
            'HWID Locking',
            'Session Management',
            'Rate Limiting',
            'IP Validation',
            'Anti-Bypass Protection',
            'Request Fingerprinting',
            'Multi-Layer Obfuscation',
            'Instant Updates',
            'Analytics & Monitoring',
          ],
          endpoints: {
            gateway: '/api/gateway',
            validate: '/api/auth/validate',
            hwid: '/api/auth/hwid',
            session: '/api/auth/session',
            loader: '/api/scripts/loader',
            encrypt: '/api/scripts/encrypt',
            keys: '/api/admin/keys',
            dashboard: '/api/admin/dashboard',
            analytics: '/api/admin/analytics',
          },
          security: {
            encryption: 'AES-256-GCM',
            keyDerivation: 'PBKDF2-SHA512 (100k iterations)',
            transport: 'TLS 1.3 (Vercel Edge)',
            obfuscation: '3-layer runtime',
          },
          loadTime: `${Date.now() - startTime}ms`,
          requestId,
        });
      }
      
      // ─────────────────────────────────────
      // FULL AUTH + LOAD (Single Request)
      // For simpler integrations
      // ─────────────────────────────────────
      case 'execute': {
        const { key, hwid, scriptId, projectId } = body;
        
        if (!key || !hwid) {
          return Utils.error(res, 400, 'key and hwid are required', 'MISSING_FIELDS');
        }
        
        // Auth rate limit
        const authRL = RateLimiter.checkAuth(ip);
        if (!authRL.allowed) {
          return Utils.error(res, 429, 'Too many attempts', 'RATE_LIMITED');
        }
        
        // IP validation
        const ipCheck = IPGuard.validate(ip);
        if (!ipCheck.valid) {
          return Utils.error(res, 403, ipCheck.reason, ipCheck.code);
        }
        
        // Anti-bypass
        const bypassCheck = AntiBypass.validateRequest(req, body);
        if (!bypassCheck.valid && bypassCheck.score < 50) {
          Database.recordFailedAttempt(ip);
          IPGuard.checkAndAutoBlacklist(ip);
          return Utils.error(res, 403, 'Security validation failed', 'BYPASS_DETECTED');
        }
        
        // Key validation
        const keyRecord = Database.getKey(key);
        if (!keyRecord) {
          Database.recordFailedAttempt(ip);
          IPGuard.checkAndAutoBlacklist(ip);
          return Utils.error(res, 401, 'Invalid key', 'INVALID_KEY');
        }
        
        if (keyRecord.status !== 'active') {
          return Utils.error(res, 403, `Key is ${keyRecord.status}`, 'KEY_INACTIVE');
        }
        
        if (keyRecord.expiresAt && keyRecord.expiresAt < Date.now()) {
          Database.updateKey(key, { status: 'expired' });
          return Utils.error(res, 403, 'Key expired', 'KEY_EXPIRED');
        }
        
        // HWID check
        if (keyRecord.hwid && keyRecord.hwid !== hwid) {
          Database.recordFailedAttempt(ip);
          return Utils.error(res, 403, 'HWID mismatch', 'HWID_MISMATCH');
        }
        
        if (!keyRecord.hwid) {
          Database.updateKey(key, { hwid });
        }
        
        // IP whitelist per-key
        if (keyRecord.allowedIPs.length > 0 && !keyRecord.allowedIPs.includes(ip)) {
          return Utils.error(res, 403, 'IP not authorized', 'IP_NOT_AUTHORIZED');
        }
        
        // Create session
        const fingerprint = Fingerprint.generate(req);
        const existingSessions = Database.getSessionsByKey(keyRecord.id);
        if (existingSessions.length >= keyRecord.maxSessions) {
          const oldest = existingSessions.sort((a, b) => a.createdAt - b.createdAt)[0];
          Database.deleteSession(oldest.token);
        }
        
        const session = Database.createSession({
          keyId: keyRecord.id,
          ip,
          hwid,
          fingerprint,
          ttl: 300000,
        });
        
        // Script delivery
        const masterKey = process.env.MASTER_KEY;
        if (!masterKey) {
          return Utils.error(res, 500, 'Server not configured', 'CONFIG_ERROR');
        }
        
        let targetScriptId = scriptId;
        if (!targetScriptId && projectId) {
          const project = Database.getProject(projectId);
          if (project?.scriptId) targetScriptId = project.scriptId;
        }
        if (!targetScriptId) {
          const scripts = Database.getAllScripts(projectId);
          if (scripts.length > 0) targetScriptId = scripts[0].id;
        }
        
        if (!targetScriptId) {
          return Utils.success(res, {
            session: {
              token: session.token,
              expiresAt: session.expiresAt,
            },
            script: null,
            message: 'Authenticated but no script configured',
          }, 'Auth successful, no script');
        }
        
        const decrypted = Database.decryptScript(targetScriptId, masterKey);
        if (!decrypted) {
          return Utils.error(res, 500, 'Script decryption failed', 'DECRYPT_ERROR');
        }
        
        // Obfuscate
        const obfuscated = Obfuscator.obfuscate(decrypted, {
          layers: 3,
          sessionToken: session.token,
          expiresAt: session.expiresAt,
        });
        
        // Update stats
        Database.updateKey(keyRecord.id, {
          lastUsed: Date.now(),
          totalExecutions: keyRecord.totalExecutions + 1,
        });
        
        Database.clearFailedAttempts(ip);
        
        const loadTime = Date.now() - startTime;
        Database.recordEvent({
          type: 'execute_success',
          keyId: keyRecord.id,
          ip,
          data: { loadTimeMs: loadTime, scriptId: targetScriptId }
        });
        
        res.setHeader('X-Load-Time', `${loadTime}ms`);
        res.setHeader('X-Request-Id', requestId);
        
        return Utils.success(res, {
          session: {
            token: session.token,
            expiresAt: session.expiresAt,
          },
          script: obfuscated.source,
          meta: {
            version: Database.getScript(targetScriptId)?.version,
            loadTimeMs: loadTime,
            layers: obfuscated.layers,
          },
          requestId,
        }, 'Script delivered');
      }
      
      // ─────────────────────────────────────
      // ADMIN: Quick key operations via gateway
      // ─────────────────────────────────────
      case 'admin.createKey': {
        const adminKey = body.adminKey || req.headers['x-api-key'];
        const expected = process.env.ADMIN_KEY || process.env.MASTER_KEY;
        if (!adminKey || adminKey !== expected) {
          return Utils.error(res, 403, 'Unauthorized', 'UNAUTHORIZED');
        }
        
        const keyData = {
          projectId: body.projectId || 'default',
          prefix: body.prefix || 'SS',
          type: body.type || 'standard',
          maxSessions: body.maxSessions || 1,
          expiresAt: body.expiresAt || null,
          note: body.note || '',
        };
        
        if (body.duration) {
          const durations = {
            '1h': 3600000, '1d': 86400000, '7d': 604800000,
            '30d': 2592000000, 'lifetime': null,
          };
          keyData.expiresAt = durations[body.duration] 
            ? Date.now() + durations[body.duration] : null;
        }
        
        const count = Math.min(body.count || 1, 50);
        const keys = [];
        for (let i = 0; i < count; i++) {
          keys.push(Database.createKey(keyData));
        }
        
        return Utils.success(res, {
          keys: keys.map(k => ({ key: k.key, type: k.type, expiresAt: k.expiresAt })),
        }, `${count} key(s) created`);
      }
      
      case 'admin.storeScript': {
        const adminKey = body.adminKey || req.headers['x-api-key'];
        const expected = process.env.ADMIN_KEY || process.env.MASTER_KEY;
        if (!adminKey || adminKey !== expected) {
          return Utils.error(res, 403, 'Unauthorized');
        }
        
        const masterKey = process.env.MASTER_KEY;
        if (!masterKey) return Utils.error(res, 500, 'MASTER_KEY not configured');
        if (!body.source) return Utils.error(res, 400, 'source required');
        
        const script = Database.storeScript({
          id: body.scriptId,
          projectId: body.projectId || 'default',
          name: body.name || 'Script',
          version: body.version || '1.0.0',
          source: body.source,
        }, masterKey);
        
        return Utils.success(res, { script }, 'Script encrypted and stored');
      }
      
      case 'admin.stats': {
        const adminKey = body.adminKey || req.headers['x-api-key'];
        const expected = process.env.ADMIN_KEY || process.env.MASTER_KEY;
        if (!adminKey || adminKey !== expected) {
          return Utils.error(res, 403, 'Unauthorized');
        }
        
        return Utils.success(res, {
          stats: Database.getStats(),
          uptime: process.uptime(),
        });
      }
      
      // ─────────────────────────────────────
      // DEFAULT
      // ─────────────────────────────────────
      default:
        return Utils.error(res, 400, `Unknown action: ${action}`, 'UNKNOWN_ACTION');
    }
    
  } catch (err) {
    Database.recordEvent({ type: 'gateway_error', ip, data: { error: err.message } });
    return Utils.error(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  }
};
