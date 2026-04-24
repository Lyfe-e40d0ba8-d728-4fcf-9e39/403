// api/security/antibypass.js
// ============================================
// ANTI-BYPASS PROTECTION SYSTEM
// ============================================

const CryptoEngine = require('../../lib/crypto');
const Utils = require('../../lib/utils');
const Database = require('../../lib/database');

class AntiBypass {
  
  /**
   * Validate request integrity
   */
  static validateRequest(req, body = {}) {
    const checks = [];
    
    // 1. Check required headers
    checks.push(this.checkRequiredHeaders(req));
    
    // 2. Check request signature (if provided)
    checks.push(this.checkRequestSignature(req, body));
    
    // 3. Check timestamp freshness
    checks.push(this.checkTimestamp(req));
    
    // 4. Check for replay attack
    checks.push(this.checkReplay(req));
    
    // 5. Check User-Agent consistency
    checks.push(this.checkUserAgent(req));
    
    const failed = checks.filter(c => !c.passed);
    
    return {
      valid: failed.length === 0,
      score: ((checks.length - failed.length) / checks.length) * 100,
      checks,
      failedChecks: failed.map(f => f.name),
    };
  }
  
  /**
   * Check required headers are present
   */
  static checkRequiredHeaders(req) {
    const required = ['content-type'];
    const missing = required.filter(h => !req.headers[h]);
    
    return {
      name: 'required_headers',
      passed: missing.length === 0,
      detail: missing.length ? `Missing: ${missing.join(', ')}` : 'OK'
    };
  }
  
  /**
   * Verify request signature
   */
  static checkRequestSignature(req, body) {
    const signature = req.headers['x-request-signature'];
    
    // If no signature system is being used, pass
    if (!signature && !process.env.REQUIRE_SIGNATURES) {
      return { name: 'request_signature', passed: true, detail: 'Not required' };
    }
    
    if (!signature) {
      return { name: 'request_signature', passed: false, detail: 'Missing signature' };
    }
    
    const secret = process.env.SIGNATURE_SECRET || process.env.MASTER_KEY;
    if (!secret) {
      return { name: 'request_signature', passed: true, detail: 'No secret configured' };
    }
    
    const payload = JSON.stringify(body) + (req.headers['x-timestamp'] || '');
    const expected = CryptoEngine.hmac(payload, secret);
    
    return {
      name: 'request_signature',
      passed: CryptoEngine.safeCompare(signature, expected),
      detail: CryptoEngine.safeCompare(signature, expected) ? 'Valid' : 'Invalid signature'
    };
  }
  
  /**
   * Check request timestamp freshness (anti-replay)
   */
  static checkTimestamp(req) {
    const timestamp = req.headers['x-timestamp'];
    
    if (!timestamp) {
      return { name: 'timestamp', passed: true, detail: 'No timestamp provided' };
    }
    
    const requestTime = parseInt(timestamp);
    const now = Date.now();
    const maxAge = 30000; // 30 seconds
    
    const isValid = !isNaN(requestTime) && Math.abs(now - requestTime) < maxAge;
    
    return {
      name: 'timestamp',
      passed: isValid,
      detail: isValid ? 'Fresh' : 'Stale or invalid timestamp'
    };
  }
  
  /**
   * Check for replay attacks using nonce
   */
  static checkReplay(req) {
    const nonce = req.headers['x-nonce'];
    
    if (!nonce) {
      return { name: 'replay', passed: true, detail: 'No nonce provided' };
    }
    
    // Check if nonce was already used
    const nonceKey = `nonce:${nonce}`;
    const rateCheck = Database.checkRateLimit(nonceKey, 1, 300000); // 5 min window
    
    return {
      name: 'replay',
      passed: rateCheck.allowed,
      detail: rateCheck.allowed ? 'Unique request' : 'Duplicate nonce detected'
    };
  }
  
  /**
   * Check User-Agent consistency
   */
  static checkUserAgent(req) {
    const ua = req.headers['user-agent'] || '';
    
    // Flag known exploit tools
    const suspiciousAgents = [
      'curl', 'wget', 'postman',
      'insomnia', 'httpie', 'python-requests',
      'go-http-client', 'java/',
    ];
    
    // Only flag in strict mode
    if (!process.env.STRICT_UA_CHECK) {
      return { name: 'user_agent', passed: true, detail: 'Strict mode off' };
    }
    
    const isSuspicious = suspiciousAgents.some(s => 
      ua.toLowerCase().includes(s)
    );
    
    return {
      name: 'user_agent',
      passed: !isSuspicious,
      detail: isSuspicious ? `Suspicious UA: ${ua.substring(0, 50)}` : 'OK'
    };
  }
  
  /**
   * Generate client-side validation token
   */
  static generateValidationChallenge() {
    const challenge = CryptoEngine.generateSessionToken();
    const answer = CryptoEngine.hash(challenge + (process.env.MASTER_KEY || 'default'));
    
    return {
      challenge,
      expectedAnswer: answer.substring(0, 16),
    };
  }
}

module.exports = AntiBypass;

module.exports.default = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const body = await Utils.parseBody(req);
  const result = AntiBypass.validateRequest(req, body);
  
  return Utils.success(res, { antiBypass: result });
};
