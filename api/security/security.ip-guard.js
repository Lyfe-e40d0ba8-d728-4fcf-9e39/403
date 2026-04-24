// api/security/ipguard.js
// ============================================
// IP VALIDATION & GUARD
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');

class IPGuard {
  
  /**
   * Full IP validation pipeline
   */
  static validate(ip, allowedIPs = []) {
    // Check blacklist first
    if (Database.isBlacklisted(ip)) {
      return {
        valid: false,
        reason: 'IP is blacklisted',
        code: 'IP_BLACKLISTED'
      };
    }
    
    // Check if IP format is valid
    if (!Utils.isValidIP(ip) && ip !== 'unknown') {
      return {
        valid: false,
        reason: 'Invalid IP format',
        code: 'INVALID_IP'
      };
    }
    
    // Check allowed IPs whitelist (if configured)
    if (allowedIPs.length > 0 && !allowedIPs.includes(ip)) {
      return {
        valid: false,
        reason: 'IP not in whitelist',
        code: 'IP_NOT_WHITELISTED'
      };
    }
    
    // Check for known proxy/VPN patterns (basic)
    if (this.isSuspiciousIP(ip)) {
      return {
        valid: false,
        reason: 'Suspicious IP detected',
        code: 'SUSPICIOUS_IP'
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Basic suspicious IP detection
   */
  static isSuspiciousIP(ip) {
    const suspicious = [
      /^0\./,           // Invalid range
      /^127\./,         // Loopback (unless testing)
      /^10\./,          // Private (might be legit behind NAT)
    ];
    
    // Only flag truly suspicious, not private ranges
    // since Vercel resolves the real IP
    return ip === '0.0.0.0';
  }
  
  /**
   * Check for failed attempts and auto-blacklist
   */
  static checkAndAutoBlacklist(ip, maxAttempts = 5, lockoutMs = 900000) {
    const attempts = Database.getFailedAttempts(ip);
    
    if (attempts >= maxAttempts) {
      Database.blacklistIP(ip, 'Too many failed attempts', lockoutMs);
      Database.recordEvent({
        type: 'auto_blacklist',
        ip,
        data: { attempts, lockoutMs }
      });
      return true;
    }
    
    return false;
  }
}

module.exports = IPGuard;

module.exports.default = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const ip = Utils.getIP(req);
  const result = IPGuard.validate(ip);
  
  return Utils.success(res, { validation: result });
};
