// lib/crypto.js
// ============================================
// AES-256-GCM ENCRYPTION ENGINE
// ============================================

const crypto = require('crypto');
const { ALGORITHM, KEY_LENGTH, IV_LENGTH, SALT_LENGTH } = require('./constants');

class CryptoEngine {
  
  /**
   * Derive encryption key from master key + salt
   */
  static deriveKey(masterKey, salt) {
    return crypto.pbkdf2Sync(masterKey, salt, 100000, KEY_LENGTH, 'sha512');
  }
  
  /**
   * AES-256-GCM Encrypt
   * Returns: salt:iv:tag:encrypted (all hex)
   */
  static encrypt(plaintext, masterKey) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = this.deriveKey(masterKey, salt);
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return [
      salt.toString('hex'),
      iv.toString('hex'),
      tag.toString('hex'),
      encrypted
    ].join(':');
  }
  
  /**
   * AES-256-GCM Decrypt
   */
  static decrypt(encryptedData, masterKey) {
    const parts = encryptedData.split(':');
    if (parts.length !== 4) {
      throw new Error('Invalid encrypted data format');
    }
    
    const [saltHex, ivHex, tagHex, encrypted] = parts;
    
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const key = this.deriveKey(masterKey, salt);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  /**
   * Generate secure random key
   */
  static generateKey(prefix = 'SS') {
    const segments = [];
    for (let i = 0; i < 4; i++) {
      segments.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return `${prefix}-${segments.join('-')}`;
  }
  
  /**
   * Hash with SHA-512
   */
  static hash(data) {
    return crypto.createHash('sha512').update(data).digest('hex');
  }
  
  /**
   * HMAC-SHA256 for request signing
   */
  static hmac(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
  }
  
  /**
   * Generate session token
   */
  static generateSessionToken() {
    return crypto.randomBytes(48).toString('hex');
  }
  
  /**
   * Time-safe comparison
   */
  static safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
}

module.exports = CryptoEngine;
