// lib/utils.js
// ============================================
// UTILITY FUNCTIONS
// ============================================

class Utils {
  
  /**
   * Extract real IP from request
   */
  static getIP(req) {
    return (
      req.headers['cf-connecting-ip'] ||
      req.headers['x-real-ip'] ||
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket?.remoteAddress ||
      'unknown'
    );
  }
  
  /**
   * Parse request body
   */
  static async parseBody(req) {
    return new Promise((resolve, reject) => {
      // If body already parsed (Vercel)
      if (req.body) {
        resolve(req.body);
        return;
      }
      
      let body = '';
      req.on('data', chunk => {
        body += chunk;
        if (body.length > 1048576) { // 1MB limit
          reject(new Error('Body too large'));
        }
      });
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (e) {
          reject(new Error('Invalid JSON'));
        }
      });
      req.on('error', reject);
    });
  }
  
  /**
   * Standard JSON response
   */
  static respond(res, statusCode, data) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Request-Time', Date.now().toString());
    res.statusCode = statusCode;
    res.end(JSON.stringify(data));
  }
  
  /**
   * Success response
   */
  static success(res, data = {}, message = 'Success') {
    return this.respond(res, 200, {
      success: true,
      message,
      timestamp: Date.now(),
      ...data
    });
  }
  
  /**
   * Error response
   */
  static error(res, statusCode, message, code = 'ERROR') {
    return this.respond(res, statusCode, {
      success: false,
      error: {
        code,
        message,
      },
      timestamp: Date.now(),
    });
  }
  
  /**
   * CORS headers
   */
  static setCORS(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-HWID, X-Session-Token, X-Fingerprint, X-Request-Signature');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  
  /**
   * Validate required fields
   */
  static validateFields(obj, requiredFields) {
    const missing = [];
    for (const field of requiredFields) {
      if (obj[field] === undefined || obj[field] === null || obj[field] === '') {
        missing.push(field);
      }
    }
    return missing;
  }
  
  /**
   * Sanitize string input
   */
  static sanitize(input) {
    if (typeof input !== 'string') return input;
    return input
      .replace(/[<>]/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+=/gi, '')
      .trim()
      .substring(0, 1000);
  }
  
  /**
   * Generate request ID
   */
  static generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  /**
   * Check if key format is valid
   */
  static isValidKeyFormat(key) {
    return /^[A-Z]{2,5}-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}$/i.test(key);
  }
  
  /**
   * Check if IP format is valid
   */
  static isValidIP(ip) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4.test(ip) || ipv6.test(ip);
  }
  
  /**
   * Mask sensitive data for logging
   */
  static maskKey(key) {
    if (!key || key.length < 10) return '****';
    return key.substring(0, 6) + '****' + key.substring(key.length - 4);
  }
  
  /**
   * Calculate time remaining
   */
  static timeRemaining(expiresAt) {
    if (!expiresAt) return 'never';
    const diff = expiresAt - Date.now();
    if (diff <= 0) return 'expired';
    
    const days = Math.floor(diff / 86400000);
    const hours = Math.floor((diff % 86400000) / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  }
}

module.exports = Utils;
