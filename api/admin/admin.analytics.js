// api/admin/analytics.js
// ============================================
// ANALYTICS & REPORTING API
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const RateLimiter = require('../security/ratelimit');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const ip = Utils.getIP(req);
  const rateLimit = RateLimiter.checkAdmin(ip);
  RateLimiter.applyHeaders(res, rateLimit);
  if (!rateLimit.allowed) return Utils.error(res, 429, 'Rate limited');
  
  const adminKey = req.headers['x-api-key'];
  const expected = process.env.ADMIN_KEY || process.env.MASTER_KEY;
  if (!adminKey || adminKey !== expected) {
    return Utils.error(res, 403, 'Unauthorized');
  }
  
  try {
    const body = req.method === 'GET' ? {} : await Utils.parseBody(req);
    const action = body.action || 'summary';
    
    switch (action) {
      case 'summary': {
        const stats = Database.getStats();
        const allKeys = Database.getAllKeys();
        
        // Key type distribution
        const typeDistribution = {};
        const statusDistribution = {};
        
        allKeys.forEach(k => {
          typeDistribution[k.type] = (typeDistribution[k.type] || 0) + 1;
          statusDistribution[k.status] = (statusDistribution[k.status] || 0) + 1;
        });
        
        // Recent activity
        const events24h = Database.getAnalytics({ since: Date.now() - 86400000 });
        const eventTypes = {};
        events24h.forEach(e => {
          eventTypes[e.type] = (eventTypes[e.type] || 0) + 1;
        });
        
        return Utils.success(res, {
          overview: stats,
          keys: { typeDistribution, statusDistribution },
          activity24h: {
            totalEvents: events24h.length,
            breakdown: eventTypes,
          }
        });
      }
      
      case 'key_usage': {
        if (!body.keyId) return Utils.error(res, 400, 'keyId required');
        
        const key = Database.getKey(body.keyId);
        if (!key) return Utils.error(res, 404, 'Key not found');
        
        const events = Database.getAnalytics({ keyId: body.keyId });
        const sessions = Database.getSessionsByKey(body.keyId);
        
        return Utils.success(res, {
          key: {
            id: key.id,
            type: key.type,
            status: key.status,
            totalExecutions: key.totalExecutions,
            lastUsed: key.lastUsed,
            createdAt: key.createdAt,
          },
          activeSessions: sessions.length,
          recentEvents: events.slice(0, 50),
        });
      }
      
      case 'export': {
        const allKeys = Database.getAllKeys(body.projectId);
        const csvLines = ['Key,Type,Status,HWID,Executions,Created,Expires,LastUsed'];
        
        allKeys.forEach(k => {
          csvLines.push([
            k.key,
            k.type,
            k.status,
            k.hwid || 'unbound',
            k.totalExecutions,
            new Date(k.createdAt).toISOString(),
            k.expiresAt ? new Date(k.expiresAt).toISOString() : 'never',
            k.lastUsed ? new Date(k.lastUsed).toISOString() : 'never',
          ].join(','));
        });
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=keys_export.csv');
        return res.end(csvLines.join('\n'));
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action. Use: summary, key_usage, export');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error');
  }
};
