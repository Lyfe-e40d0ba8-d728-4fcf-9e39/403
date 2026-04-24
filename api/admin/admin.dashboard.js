// api/admin/dashboard.js
// ============================================
// ADMIN DASHBOARD API
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const RateLimiter = require('../security/ratelimit');

function verifyAdmin(req) {
  const adminKey = req.headers['x-api-key'] || '';
  const expected = process.env.ADMIN_KEY || process.env.MASTER_KEY;
  return adminKey && adminKey === expected;
}

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const ip = Utils.getIP(req);
  const rateLimit = RateLimiter.checkAdmin(ip);
  RateLimiter.applyHeaders(res, rateLimit);
  if (!rateLimit.allowed) return Utils.error(res, 429, 'Rate limited');
  
  if (!verifyAdmin(req)) {
    return Utils.error(res, 403, 'Admin authorization required');
  }
  
  try {
    const body = req.method === 'GET' ? {} : await Utils.parseBody(req);
    const action = body.action || 'overview';
    
    switch (action) {
      case 'overview': {
        const stats = Database.getStats();
        const recentEvents = Database.getAnalytics({ since: Date.now() - 3600000 });
        
        // Calculate hourly stats
        const hourAgo = Date.now() - 3600000;
        const recentAuth = recentEvents.filter(e => e.type === 'auth_success');
        const recentLoads = recentEvents.filter(e => e.type === 'script_loaded');
        const recentBlocks = recentEvents.filter(e => 
          ['rate_limited', 'ip_blocked', 'bypass_attempt'].includes(e.type)
        );
        
        return Utils.success(res, {
          stats,
          hourly: {
            authentications: recentAuth.length,
            scriptLoads: recentLoads.length,
            blocked: recentBlocks.length,
          },
          uptime: process.uptime(),
          serverTime: Date.now(),
        });
      }
      
      case 'events': {
        const events = Database.getAnalytics({
          type: body.type,
          keyId: body.keyId,
          since: body.since || Date.now() - 86400000, // Default: last 24h
        });
        
        const page = body.page || 1;
        const limit = Math.min(body.limit || 50, 200);
        const start = (page - 1) * limit;
        
        return Utils.success(res, {
          events: events.slice(start, start + limit),
          pagination: {
            total: events.length,
            page,
            limit,
          }
        });
      }
      
      case 'security': {
        return Utils.success(res, {
          blacklistedIPs: Array.from(Database.getAllKeys()).length, // placeholder
          recentThreats: Database.getAnalytics({ type: 'bypass_attempt' }).slice(0, 20),
          rateLimitHits: Database.getAnalytics({ type: 'rate_limited' }).slice(0, 20),
        });
      }
      
      case 'blacklist': {
        if (body.ip && body.operation === 'add') {
          Database.blacklistIP(body.ip, body.reason || 'Manual blacklist', body.duration);
          return Utils.success(res, {}, `IP ${body.ip} blacklisted`);
        }
        if (body.ip && body.operation === 'remove') {
          Database.removeFromBlacklist(body.ip);
          return Utils.success(res, {}, `IP ${body.ip} removed from blacklist`);
        }
        return Utils.error(res, 400, 'Specify ip and operation (add/remove)');
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error');
  }
};
