// api/admin/keys.js
// ============================================
// KEY MANAGEMENT CRUD API
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const RateLimiter = require('../security/ratelimit');

function verifyAdmin(adminKey) {
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
  
  try {
    const body = req.method === 'GET' ? {} : await Utils.parseBody(req);
    const adminKey = body.adminKey || req.headers['x-api-key'];
    
    if (!verifyAdmin(adminKey)) {
      return Utils.error(res, 403, 'Admin authorization required', 'UNAUTHORIZED');
    }
    
    const action = body.action || req.method.toLowerCase();
    
    switch (action) {
      // ── CREATE KEY ──
      case 'create':
      case 'post': {
        const keyData = {
          projectId: body.projectId || 'default',
          prefix: body.prefix || 'SS',
          type: body.type || 'standard',
          maxSessions: body.maxSessions || 1,
          allowedIPs: body.allowedIPs || [],
          expiresAt: body.expiresAt || null,
          note: body.note || '',
          metadata: body.metadata || {},
        };
        
        // Handle duration-based expiry
        if (body.duration) {
          const durations = {
            '1h': 3600000,
            '1d': 86400000,
            '7d': 604800000,
            '30d': 2592000000,
            '90d': 7776000000,
            '1y': 31536000000,
            'lifetime': null,
          };
          keyData.expiresAt = durations[body.duration] 
            ? Date.now() + durations[body.duration] 
            : null;
        }
        
        // Batch creation
        const count = Math.min(body.count || 1, 100);
        const keys = [];
        
        for (let i = 0; i < count; i++) {
          keys.push(Database.createKey(keyData));
        }
        
        Database.recordEvent({
          type: 'keys_created',
          ip,
          data: { count, type: keyData.type, projectId: keyData.projectId }
        });
        
        return Utils.success(res, { 
          keys: keys.map(k => ({
            id: k.id,
            key: k.key,
            type: k.type,
            status: k.status,
            expiresAt: k.expiresAt,
            remaining: Utils.timeRemaining(k.expiresAt),
          })),
          count 
        }, `${count} key(s) created`);
      }
      
      // ── GET KEY(S) ──
      case 'get':
      case 'list': {
        if (body.keyId) {
          const key = Database.getKey(body.keyId);
          if (!key) return Utils.error(res, 404, 'Key not found');
          return Utils.success(res, { key });
        }
        
        let keys = Database.getAllKeys(body.projectId);
        
        // Filter by status
        if (body.status) {
          keys = keys.filter(k => k.status === body.status);
        }
        
        // Pagination
        const page = body.page || 1;
        const limit = Math.min(body.limit || 50, 100);
        const start = (page - 1) * limit;
        const paged = keys.slice(start, start + limit);
        
        return Utils.success(res, {
          keys: paged,
          pagination: {
            total: keys.length,
            page,
            limit,
            pages: Math.ceil(keys.length / limit),
          }
        });
      }
      
      // ── UPDATE KEY ──
      case 'update':
      case 'put': {
        if (!body.keyId) return Utils.error(res, 400, 'keyId required');
        
        const allowedUpdates = ['status', 'type', 'maxSessions', 'allowedIPs', 'expiresAt', 'note', 'metadata'];
        const updates = {};
        
        for (const field of allowedUpdates) {
          if (body[field] !== undefined) {
            updates[field] = body[field];
          }
        }
        
        const updated = Database.updateKey(body.keyId, updates);
        if (!updated) return Utils.error(res, 404, 'Key not found');
        
        Database.recordEvent({
          type: 'key_updated',
          keyId: body.keyId,
          ip,
          data: { updates: Object.keys(updates) }
        });
        
        return Utils.success(res, { key: updated }, 'Key updated');
      }
      
      // ── DELETE KEY ──
      case 'delete': {
        if (!body.keyId) return Utils.error(res, 400, 'keyId required');
        
        // Kill all sessions first
        Database.deleteSessionsByKey(body.keyId);
        Database.deleteKey(body.keyId);
        
        Database.recordEvent({
          type: 'key_deleted',
          keyId: body.keyId,
          ip,
        });
        
        return Utils.success(res, {}, 'Key deleted');
      }
      
      // ── SUSPEND KEY ──
      case 'suspend': {
        if (!body.keyId) return Utils.error(res, 400, 'keyId required');
        
        Database.deleteSessionsByKey(body.keyId);
        const updated = Database.updateKey(body.keyId, { status: 'suspended' });
        if (!updated) return Utils.error(res, 404, 'Key not found');
        
        return Utils.success(res, { key: updated }, 'Key suspended');
      }
      
      // ── ACTIVATE KEY ──
      case 'activate': {
        if (!body.keyId) return Utils.error(res, 400, 'keyId required');
        
        const updated = Database.updateKey(body.keyId, { status: 'active' });
        if (!updated) return Utils.error(res, 404, 'Key not found');
        
        return Utils.success(res, { key: updated }, 'Key activated');
      }
      
      // ── BULK OPERATIONS ──
      case 'bulk': {
        const { operation, keyIds } = body;
        if (!keyIds || !Array.isArray(keyIds)) {
          return Utils.error(res, 400, 'keyIds array required');
        }
        
        let processed = 0;
        for (const keyId of keyIds.slice(0, 100)) {
          switch (operation) {
            case 'delete':
              Database.deleteSessionsByKey(keyId);
              Database.deleteKey(keyId);
              processed++;
              break;
            case 'suspend':
              Database.deleteSessionsByKey(keyId);
              Database.updateKey(keyId, { status: 'suspended' });
              processed++;
              break;
            case 'activate':
              Database.updateKey(keyId, { status: 'active' });
              processed++;
              break;
          }
        }
        
        return Utils.success(res, { processed }, `${processed} keys ${operation}d`);
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error');
  }
};
