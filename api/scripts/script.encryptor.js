// api/scripts/encrypt.js
// ============================================
// AES-256 SCRIPT ENCRYPTION SERVICE
// ============================================

const CryptoEngine = require('../../lib/crypto');
const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const RateLimiter = require('../security/ratelimit');

module.exports = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  if (req.method !== 'POST') return Utils.error(res, 405, 'Method not allowed');
  
  const ip = Utils.getIP(req);
  const rateLimit = RateLimiter.checkAdmin(ip);
  RateLimiter.applyHeaders(res, rateLimit);
  if (!rateLimit.allowed) return Utils.error(res, 429, 'Rate limited');
  
  try {
    const body = await Utils.parseBody(req);
    const { action, adminKey, scriptId, source, name, version, projectId } = body;
    
    // Admin auth required for all encrypt operations
    const masterKey = process.env.MASTER_KEY;
    const adminKeyEnv = process.env.ADMIN_KEY || masterKey;
    
    if (!adminKey || adminKey !== adminKeyEnv) {
      return Utils.error(res, 403, 'Admin authorization required', 'UNAUTHORIZED');
    }
    
    if (!masterKey) {
      return Utils.error(res, 500, 'MASTER_KEY not configured', 'CONFIG_ERROR');
    }
    
    switch (action) {
      case 'store': {
        if (!source) {
          return Utils.error(res, 400, 'Script source is required');
        }
        
        if (Buffer.byteLength(source, 'utf8') > 5242880) {
          return Utils.error(res, 413, 'Script too large (max 5MB)', 'SCRIPT_TOO_LARGE');
        }
        
        const script = Database.storeScript({
          id: scriptId,
          projectId: projectId || 'default',
          name: name || 'Unnamed Script',
          version: version || '1.0.0',
          source,
        }, masterKey);
        
        Database.recordEvent({
          type: 'script_stored',
          ip,
          data: { scriptId: script.id, name: script.name, size: script.size }
        });
        
        return Utils.success(res, { script }, 'Script encrypted and stored');
      }
      
      case 'update': {
        if (!scriptId || !source) {
          return Utils.error(res, 400, 'scriptId and source required');
        }
        
        const existing = Database.getScript(scriptId);
        if (!existing) {
          return Utils.error(res, 404, 'Script not found');
        }
        
        // Delete old and store new (atomic update)
        Database.deleteScript(scriptId);
        const updated = Database.storeScript({
          id: scriptId,
          projectId: existing.projectId,
          name: name || existing.name,
          version: version || this.incrementVersion(existing.version),
          source,
        }, masterKey);
        
        Database.recordEvent({
          type: 'script_updated',
          ip,
          data: { scriptId, version: updated.version }
        });
        
        return Utils.success(res, { script: updated }, 'Script updated (instant propagation)');
      }
      
      case 'delete': {
        if (!scriptId) return Utils.error(res, 400, 'scriptId required');
        
        Database.deleteScript(scriptId);
        Database.recordEvent({ type: 'script_deleted', ip, data: { scriptId } });
        
        return Utils.success(res, {}, 'Script deleted');
      }
      
      case 'list': {
        const scripts = Database.getAllScripts(projectId);
        return Utils.success(res, { scripts, count: scripts.length });
      }
      
      case 'verify': {
        if (!scriptId) return Utils.error(res, 400, 'scriptId required');
        
        const script = Database.getScript(scriptId);
        if (!script) return Utils.error(res, 404, 'Script not found');
        
        // Try to decrypt to verify integrity
        try {
          const decrypted = Database.decryptScript(scriptId, masterKey);
          return Utils.success(res, {
            integrity: {
              valid: !!decrypted,
              hash: script.hash,
              size: script.size,
              version: script.version,
            }
          });
        } catch {
          return Utils.error(res, 500, 'Script integrity check failed');
        }
      }
      
      default:
        return Utils.error(res, 400, 'Invalid action. Use: store, update, delete, list, verify');
    }
    
  } catch (err) {
    return Utils.error(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  }
};

module.exports.incrementVersion = function(version) {
  const parts = version.split('.');
  parts[2] = (parseInt(parts[2] || 0) + 1).toString();
  return parts.join('.');
};
