// api/auth/hwid.js
// ============================================
// HWID MANAGEMENT
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const RateLimiter = require('../security/ratelimit');
const IPGuard = require('../security/ipguard');
const { HWID_MAX_RESETS, HWID_RESET_COOLDOWN } = require('../../lib/constants');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  if (req.method !== 'POST') return Utils.error(res, 405, 'Method not allowed');
  
  const ip = Utils.getIP(req);
  
  // Rate limit
  const rateLimit = RateLimiter.checkAuth(ip);
  RateLimiter.applyHeaders(res, rateLimit);
  if (!rateLimit.allowed) {
    return Utils.error(res, 429, 'Too many attempts', 'RATE_LIMITED');
  }
  
  // IP check
  const ipCheck = IPGuard.validate(ip);
  if (!ipCheck.valid) {
    return Utils.error(res, 403, ipCheck.reason, ipCheck.code);
  }
  
  try {
    const body = await Utils.parseBody(req);
    const { action, key, hwid, adminKey } = body;
    
    if (!key) return Utils.error(res, 400, 'Key is required');
    
    const keyRecord = Database.getKey(key);
    if (!keyRecord) return Utils.error(res, 404, 'Key not found', 'KEY_NOT_FOUND');
    
    switch (action) {
      case 'check': {
        return Utils.success(res, {
          hwid: {
            bound: !!keyRecord.hwid,
            match: keyRecord.hwid === hwid,
            resets: keyRecord.hwidResets,
            maxResets: HWID_MAX_RESETS,
          }
        });
      }
      
      case 'reset': {
        // Verify admin key for resets
        const masterKey = process.env.ADMIN_KEY || process.env.MASTER_KEY;
        if (!adminKey || adminKey !== masterKey) {
          return Utils.error(res, 403, 'Admin authorization required', 'UNAUTHORIZED');
        }
        
        if (keyRecord.hwidResets >= HWID_MAX_RESETS) {
          return Utils.error(res, 403, 'Maximum HWID resets reached', 'MAX_RESETS');
        }
        
        if (keyRecord.lastHwidReset && 
            (Date.now() - keyRecord.lastHwidReset) < HWID_RESET_COOLDOWN) {
          return Utils.error(res, 429, 'HWID reset cooldown active', 'RESET_COOLDOWN');
        }
        
        // Kill all existing sessions
        Database.deleteSessionsByKey(keyRecord.id);
        
        Database.updateKey(keyRecord.id, {
          hwid: null,
          hwidResets: keyRecord.hwidResets + 1,
          lastHwidReset: Date.now(),
        });
        
        Database.recordEvent({
          type: 'hwid_reset',
          keyId: keyRecord.id,
          ip,
          data: { resetsUsed: keyRecord.hwidResets + 1 }
        });
        
        return Utils.success(res, {
          message: 'HWID has been reset',
          resetsRemaining: HWID_MAX_RESETS - (keyRecord.hwidResets + 1),
        });
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action. Use: check, reset');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  }
};
