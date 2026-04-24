// lib/database.js
// ============================================
// IN-MEMORY DATABASE WITH PERSISTENCE HOOKS
// ============================================
// Production: Replace with Vercel KV, Upstash Redis, or Planetscale
// This provides the same interface for easy migration

const CryptoEngine = require('./crypto');

// ── In-Memory Storage ──
const store = {
  keys: new Map(),
  sessions: new Map(),
  scripts: new Map(),
  rateLimits: new Map(),
  blacklist: new Map(),
  analytics: new Map(),
  hwidMappings: new Map(),
  failedAttempts: new Map(),
  projects: new Map(),
};

// ── Auto-cleanup interval ──
const CLEANUP_INTERVAL = 60000; // 1 minute

function cleanup() {
  const now = Date.now();
  
  // Clean expired sessions
  for (const [key, session] of store.sessions) {
    if (session.expiresAt < now) {
      store.sessions.delete(key);
    }
  }
  
  // Clean old rate limit entries
  for (const [key, data] of store.rateLimits) {
    if (data.windowStart + 60000 < now) {
      store.rateLimits.delete(key);
    }
  }
  
  // Clean expired blacklist
  for (const [key, data] of store.blacklist) {
    if (data.expiresAt && data.expiresAt < now) {
      store.blacklist.delete(key);
    }
  }
}

setInterval(cleanup, CLEANUP_INTERVAL);

class Database {
  
  // ════════════════════════════════════════
  // KEY MANAGEMENT
  // ════════════════════════════════════════
  
  static createKey(keyData) {
    const id = CryptoEngine.generateKey(keyData.prefix || 'SS');
    const record = {
      id,
      key: id,
      projectId: keyData.projectId || 'default',
      hwid: null,
      hwidResets: 0,
      lastHwidReset: null,
      status: 'active',           // active, suspended, expired, revoked
      type: keyData.type || 'standard', // standard, premium, trial
      maxSessions: keyData.maxSessions || 1,
      activeSessions: 0,
      allowedIPs: keyData.allowedIPs || [],  // empty = allow all
      metadata: keyData.metadata || {},
      expiresAt: keyData.expiresAt || null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastUsed: null,
      totalExecutions: 0,
      note: keyData.note || '',
    };
    
    store.keys.set(id, record);
    return record;
  }
  
  static getKey(keyId) {
    return store.keys.get(keyId) || null;
  }
  
  static updateKey(keyId, updates) {
    const key = store.keys.get(keyId);
    if (!key) return null;
    
    const updated = { ...key, ...updates, updatedAt: Date.now() };
    store.keys.set(keyId, updated);
    return updated;
  }
  
  static deleteKey(keyId) {
    return store.keys.delete(keyId);
  }
  
  static getAllKeys(projectId = null) {
    const keys = Array.from(store.keys.values());
    if (projectId) {
      return keys.filter(k => k.projectId === projectId);
    }
    return keys;
  }
  
  static findKeysByStatus(status) {
    return Array.from(store.keys.values()).filter(k => k.status === status);
  }
  
  // ════════════════════════════════════════
  // SESSION MANAGEMENT
  // ════════════════════════════════════════
  
  static createSession(sessionData) {
    const token = CryptoEngine.generateSessionToken();
    const record = {
      token,
      keyId: sessionData.keyId,
      ip: sessionData.ip,
      hwid: sessionData.hwid,
      fingerprint: sessionData.fingerprint || null,
      userAgent: sessionData.userAgent || null,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      expiresAt: Date.now() + (sessionData.ttl || 300000),
      requestCount: 0,
    };
    
    store.sessions.set(token, record);
    return record;
  }
  
  static getSession(token) {
    const session = store.sessions.get(token);
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      store.sessions.delete(token);
      return null;
    }
    return session;
  }
  
  static updateSession(token, updates) {
    const session = store.sessions.get(token);
    if (!session) return null;
    
    const updated = { ...session, ...updates, lastActivity: Date.now() };
    store.sessions.set(token, updated);
    return updated;
  }
  
  static deleteSession(token) {
    return store.sessions.delete(token);
  }
  
  static getSessionsByKey(keyId) {
    return Array.from(store.sessions.values()).filter(s => s.keyId === keyId);
  }
  
  static deleteSessionsByKey(keyId) {
    for (const [token, session] of store.sessions) {
      if (session.keyId === keyId) {
        store.sessions.delete(token);
      }
    }
  }
  
  // ════════════════════════════════════════
  // SCRIPT STORAGE (ENCRYPTED)
  // ════════════════════════════════════════
  
  static storeScript(scriptData, masterKey) {
    const id = scriptData.id || `script_${Date.now()}`;
    const encryptedSource = CryptoEngine.encrypt(scriptData.source, masterKey);
    
    const record = {
      id,
      projectId: scriptData.projectId || 'default',
      name: scriptData.name || 'Unnamed Script',
      version: scriptData.version || '1.0.0',
      encryptedSource,
      hash: CryptoEngine.hash(scriptData.source),
      size: Buffer.byteLength(scriptData.source, 'utf8'),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      accessCount: 0,
    };
    
    store.scripts.set(id, record);
    return { ...record, encryptedSource: '[ENCRYPTED]' };
  }
  
  static getScript(scriptId) {
    return store.scripts.get(scriptId) || null;
  }
  
  static decryptScript(scriptId, masterKey) {
    const script = store.scripts.get(scriptId);
    if (!script) return null;
    
    try {
      const source = CryptoEngine.decrypt(script.encryptedSource, masterKey);
      store.scripts.set(scriptId, { 
        ...script, 
        accessCount: script.accessCount + 1 
      });
      return source;
    } catch (e) {
      return null;
    }
  }
  
  static deleteScript(scriptId) {
    return store.scripts.delete(scriptId);
  }
  
  static getAllScripts(projectId = null) {
    const scripts = Array.from(store.scripts.values()).map(s => ({
      ...s,
      encryptedSource: '[ENCRYPTED]'
    }));
    if (projectId) {
      return scripts.filter(s => s.projectId === projectId);
    }
    return scripts;
  }
  
  // ════════════════════════════════════════
  // RATE LIMITING
  // ════════════════════════════════════════
  
  static checkRateLimit(identifier, maxRequests, windowMs) {
    const now = Date.now();
    const key = `rl:${identifier}`;
    let data = store.rateLimits.get(key);
    
    if (!data || (now - data.windowStart) > windowMs) {
      data = { windowStart: now, count: 0, requests: [] };
    }
    
    // Clean old requests outside window
    data.requests = data.requests.filter(t => (now - t) < windowMs);
    data.count = data.requests.length;
    
    if (data.count >= maxRequests) {
      store.rateLimits.set(key, data);
      return {
        allowed: false,
        remaining: 0,
        resetAt: data.windowStart + windowMs,
        retryAfter: Math.ceil((data.windowStart + windowMs - now) / 1000)
      };
    }
    
    data.requests.push(now);
    data.count++;
    store.rateLimits.set(key, data);
    
    return {
      allowed: true,
      remaining: maxRequests - data.count,
      resetAt: data.windowStart + windowMs,
      retryAfter: 0
    };
  }
  
  // ════════════════════════════════════════
  // BLACKLIST / SECURITY
  // ════════════════════════════════════════
  
  static blacklistIP(ip, reason, duration = null) {
    store.blacklist.set(`ip:${ip}`, {
      type: 'ip',
      value: ip,
      reason,
      createdAt: Date.now(),
      expiresAt: duration ? Date.now() + duration : null,
      permanent: !duration,
    });
  }
  
  static isBlacklisted(ip) {
    const entry = store.blacklist.get(`ip:${ip}`);
    if (!entry) return false;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      store.blacklist.delete(`ip:${ip}`);
      return false;
    }
    return true;
  }
  
  static removeFromBlacklist(ip) {
    return store.blacklist.delete(`ip:${ip}`);
  }
  
  // ════════════════════════════════════════
  // FAILED ATTEMPTS TRACKING
  // ════════════════════════════════════════
  
  static recordFailedAttempt(identifier) {
    const key = `fail:${identifier}`;
    let data = store.failedAttempts.get(key) || { count: 0, attempts: [] };
    
    data.attempts.push(Date.now());
    data.count++;
    
    // Keep only last hour
    const oneHourAgo = Date.now() - 3600000;
    data.attempts = data.attempts.filter(t => t > oneHourAgo);
    data.count = data.attempts.length;
    
    store.failedAttempts.set(key, data);
    return data.count;
  }
  
  static getFailedAttempts(identifier) {
    const data = store.failedAttempts.get(`fail:${identifier}`);
    return data ? data.count : 0;
  }
  
  static clearFailedAttempts(identifier) {
    store.failedAttempts.delete(`fail:${identifier}`);
  }
  
  // ════════════════════════════════════════
  // ANALYTICS
  // ════════════════════════════════════════
  
  static recordEvent(event) {
    const id = `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const record = {
      id,
      type: event.type,
      keyId: event.keyId || null,
      ip: event.ip || null,
      data: event.data || {},
      timestamp: Date.now(),
    };
    
    store.analytics.set(id, record);
    
    // Keep max 10000 events
    if (store.analytics.size > 10000) {
      const oldest = Array.from(store.analytics.keys())[0];
      store.analytics.delete(oldest);
    }
    
    return record;
  }
  
  static getAnalytics(filter = {}) {
    let events = Array.from(store.analytics.values());
    
    if (filter.type) {
      events = events.filter(e => e.type === filter.type);
    }
    if (filter.keyId) {
      events = events.filter(e => e.keyId === filter.keyId);
    }
    if (filter.since) {
      events = events.filter(e => e.timestamp >= filter.since);
    }
    
    return events.sort((a, b) => b.timestamp - a.timestamp);
  }
  
  // ════════════════════════════════════════
  // PROJECT MANAGEMENT
  // ════════════════════════════════════════
  
  static createProject(projectData) {
    const id = projectData.id || `proj_${Date.now()}`;
    const record = {
      id,
      name: projectData.name,
      description: projectData.description || '',
      scriptId: projectData.scriptId || null,
      settings: {
        hwidLock: true,
        maxSessions: 1,
        allowedIPs: [],
        rateLimitOverride: null,
        obfuscationLevel: 3,
        ...projectData.settings,
      },
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    
    store.projects.set(id, record);
    return record;
  }
  
  static getProject(projectId) {
    return store.projects.get(projectId) || null;
  }
  
  static getAllProjects() {
    return Array.from(store.projects.values());
  }
  
  static updateProject(projectId, updates) {
    const project = store.projects.get(projectId);
    if (!project) return null;
    
    const updated = { ...project, ...updates, updatedAt: Date.now() };
    store.projects.set(projectId, updated);
    return updated;
  }
  
  // ════════════════════════════════════════
  // STATISTICS
  // ════════════════════════════════════════
  
  static getStats() {
    return {
      totalKeys: store.keys.size,
      activeKeys: Array.from(store.keys.values()).filter(k => k.status === 'active').length,
      activeSessions: store.sessions.size,
      totalScripts: store.scripts.size,
      blacklistedIPs: store.blacklist.size,
      totalEvents: store.analytics.size,
      totalProjects: store.projects.size,
    };
  }
}

module.exports = Database;
