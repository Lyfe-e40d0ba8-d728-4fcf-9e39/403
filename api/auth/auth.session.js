// api/auth/session.js
// ============================================
// SESSION TOKEN MANAGEMENT
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const Fingerprint = require('../security/fingerprint');
const RateLimiter = require('../security/ratelimit');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  if (req.method !== 'POST') return Utils.error(res, 405, 'Method not allowed');
  
  const ip = Utils.getIP(req);
  
  const rateLimit = RateLimiter.checkGeneral(ip);
  RateLimiter.applyHeaders(res, rateLimit);
  if (!rateLimit.allowed) {
    return Utils.error(res, 429, 'Rate limited', 'RATE_LIMITED');
  }
  
  try {
    const body = await Utils.parseBody(req);
    const { action, sessionToken } = body;
    
    switch (action) {
      case 'validate': {
        if (!sessionToken) {
          return Utils.error(res, 400, 'Session token required');
        }
        
        const session = Database.getSession(sessionToken);
        if (!session) {
          return Utils.error(res, 401, 'Invalid or expired session', 'SESSION_INVALID');
        }
        
        // Verify IP consistency
        if (session.ip !== ip) {
          Database.recordEvent({
            type: 'session_ip_mismatch',
            keyId: session.keyId,
            ip,
            data: { originalIP: session.ip, currentIP: ip }
          });
          // Don't immediately fail, but log it
        }
        
        // Verify fingerprint consistency
        const currentFP = Fingerprint.generate(req);
        if (!Fingerprint.compare(session.fingerprint, currentFP)) {
          Database.deleteSession(sessionToken);
          Database.recordEvent({
            type: 'session_fingerprint_mismatch',
            keyId: session.keyId,
            ip,
          });
          return Utils.error(res, 401, 'Session fingerprint mismatch', 'FINGERPRINT_MISMATCH');
        }
        
        // Update session activity
        Database.updateSession(sessionToken, {
          requestCount: session.requestCount + 1,
        });
        
        return Utils.success(res, {
          session: {
            valid: true,
            keyId: session.keyId,
            expiresAt: session.expiresAt,
            remaining: Utils.timeRemaining(session.expiresAt),
            requestCount: session.requestCount + 1,
          }
        });
      }
      
      case 'revoke': {
        if (!sessionToken) {
          return Utils.error(res, 400, 'Session token required');
        }
        
        Database.deleteSession(sessionToken);
        return Utils.success(res, { message: 'Session revoked' });
      }
      
      case 'refresh': {
        if (!sessionToken) {
          return Utils.error(res, 400, 'Session token required');
        }
        
        const session = Database.getSession(sessionToken);
        if (!session) {
          return Utils.error(res, 401, 'Session not found', 'SESSION_NOT_FOUND');
        }
        
        // Extend session
        const newExpiry = Date.now() + 300000;
        Database.updateSession(sessionToken, { expiresAt: newExpiry });
        
        return Utils.success(res, {
          session: {
            token: sessionToken,
            expiresAt: newExpiry,
            remaining: '5m',
          }
        });
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action. Use: validate, revoke, refresh');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  }
};
