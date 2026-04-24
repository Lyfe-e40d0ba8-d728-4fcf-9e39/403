// api/security/fingerprint.js
// ============================================
// REQUEST FINGERPRINTING
// ============================================

const CryptoEngine = require('../../lib/crypto');
const Utils = require('../../lib/utils');

class Fingerprint {
  
  /**
   * Generate fingerprint from request
   */
  static generate(req) {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.headers['accept'] || '',
      // Don't include IP as it may change
    ];
    
    const raw = components.join('|');
    return CryptoEngine.hash(raw).substring(0, 32);
  }
  
  /**
   * Compare two fingerprints with tolerance
   */
  static compare(fp1, fp2, tolerance = 0.7) {
    if (!fp1 || !fp2) return true; // Can't compare, allow
    if (fp1 === fp2) return true;
    
    // Simple character-level similarity
    let matches = 0;
    const len = Math.min(fp1.length, fp2.length);
    for (let i = 0; i < len; i++) {
      if (fp1[i] === fp2[i]) matches++;
    }
    
    return (matches / len) >= tolerance;
  }
  
  /**
   * Create a detailed fingerprint object
   */
  static detailed(req) {
    return {
      hash: this.generate(req),
      userAgent: req.headers['user-agent'] || 'unknown',
      language: req.headers['accept-language'] || 'unknown',
      encoding: req.headers['accept-encoding'] || 'unknown',
      ip: Utils.getIP(req),
      timestamp: Date.now(),
    };
  }
}

module.exports = Fingerprint;

module.exports.default = async function handler(req, res) {
  Utils.setCORS(res);
  if (req.method === 'OPTIONS') return Utils.success(res);
  
  const fp = Fingerprint.detailed(req);
  return Utils.success(res, { fingerprint: fp });
};
