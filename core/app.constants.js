// lib/constants.js
// ============================================
// SYSTEM CONSTANTS & CONFIGURATION
// ============================================

module.exports = {
  // Encryption
  ALGORITHM: 'aes-256-gcm',
  KEY_LENGTH: 32,
  IV_LENGTH: 16,
  TAG_LENGTH: 16,
  SALT_LENGTH: 64,
  
  // Rate Limiting
  RATE_LIMIT_WINDOW: 60000,       // 1 minute
  RATE_LIMIT_MAX_REQUESTS: 30,    // 30 requests per window
  RATE_LIMIT_LOADER_MAX: 10,      // 10 script loads per window
  
  // Session
  SESSION_TTL: 300000,            // 5 minutes
  SESSION_MAX_ACTIVE: 3,          // Max concurrent sessions
  
  // HWID
  HWID_MAX_RESETS: 3,             // Max HWID resets
  HWID_RESET_COOLDOWN: 86400000, // 24 hours
  
  // Script
  SCRIPT_CACHE_TTL: 60000,        // 1 minute cache
  MAX_SCRIPT_SIZE: 5242880,       // 5MB
  
  // Security
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION: 900000,       // 15 minutes
  FINGERPRINT_TOLERANCE: 0.7,
  
  // Obfuscation layers
  OBFUSCATION_LAYERS: 3,
  VARIABLE_NAME_LENGTH: 16,
  
  // Admin
  ADMIN_SESSION_TTL: 3600000,     // 1 hour
};
