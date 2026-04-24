// api/security/ratelimit.js
// ============================================
// ADVANCED RATE LIMITING ENGINE
// ============================================

const Database = require('../../lib/database');
const Utils = require('../../lib/utils');
const { RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_LOADER_MAX } = require('../../lib/constants');

class RateLimiter {
  
  /**
   * Check general API rate limit
   */
  static checkGeneral(ip) {
    return Database.checkRateLimit(
      `general:${ip}`,
      RATE_LIMIT_MAX_REQUESTS,
      RATE_LIMIT_WINDOW
    );
  }
  
  /**
   * Check script loader rate limit (stricter)
   */
  static checkLoader(ip) {
    return Database.checkRateLimit(
      `loader:${ip}`,
      RATE_LIMIT_LOADER_MAX,
      RATE_LIMIT_WINDOW
    );
  }
  
  /**
   * Check auth attempt rate limit (very strict)
   */
  static checkAuth(ip) {
    return Database.checkRateLimit(
      `auth:${ip}`,
      5,               // 5 attempts
      300000            // per 5 minutes
    );
  }
  
  /**
   * Check admin rate limit
   */
  static checkAdmin(ip) {
    return Database.checkRateLimit(
      `admin:${ip}`,
      60,
      RATE_LIMIT_WINDOW
    );
  }
  
  /**
   * Apply rate limit headers to response
   */
  static applyHeaders(res, result) {
    res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
    res.setHeader('X-RateLimit-Reset', result.resetAt.toString());
    
    if (!result.allowed) {
      res.setHeader('Retry-After', result.retryAfter.toString());
    }
  }
}

module.exports = RateLimiter;

// Serverless handler
module.exports.default = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const ip = Utils.getIP(req);
  const result = RateLimiter.checkGeneral(ip);
  RateLimiter.applyHeaders(res, result);
  
  return Utils.success(res, { rateLimit: result });
};
