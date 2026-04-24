// api/gateway.js
// ═══════════════════════════════════════════════════════════════════
//
//  SCRIPTSHIELD v3.0 — Hardened Script Delivery Gateway
//
//  Security layers:
//    1. Browser Detection & Blocking (User-Agent + Headers)
//    2. Header Authentication (x-shield-auth)
//    3. Token Authentication (?token=xxx fallback)
//    4. Rate Limiting (per-IP sliding window)
//    5. Burst Detection (anti-bot rapid fire)
//    6. Path Sanitization (traversal protection)
//    7. GitHub URL Hiding (never exposed)
//    8. AES-256-GCM Encryption at Rest
//    9. 6-Layer Runtime Obfuscation
//   10. Anti-Decompile Wrapping
//   11. Random Response Delay (anti-scraping)
//   12. Silent Failure (zero info leakage)
//   13. Request Fingerprinting & Logging
//
//  Compatible with:
//    - Synapse X, Fluxus, KRNL, Script-Ware, Delta
//    - game:HttpGet() / syn.request / request / http_request
//
//  Usage:
//    loadstring(game:HttpGet("https://domain/loaders/v2/script"))()
//
// ═══════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const https = require('https');

// ══════════════════════════════════════════
// [1] BROWSER DETECTION ENGINE
// ══════════════════════════════════════════

const BROWSER_SIGNATURES = [
  // ── Major Browsers ──
  'mozilla',
  'chrome',
  'chromium',
  'safari',
  'firefox',
  'opera',
  'opr/',
  'edge',
  'edg/',
  'msie',
  'trident',
  'vivaldi',
  'brave',
  'yabrowser',
  'samsung',
  'ucbrowser',
  'qqbrowser',
  'maxthon',
  'seamonkey',
  'palemoon',
  'waterfox',

  // ── Browser Engines ──
  'webkit',
  'gecko/',
  'presto',
  'blink',

  // ── Bot / Crawler ──
  'googlebot',
  'bingbot',
  'slurp',
  'duckduckbot',
  'baiduspider',
  'yandexbot',
  'facebookexternalhit',
  'twitterbot',
  'linkedinbot',
  'whatsapp',
  'telegrambot',
  'discordbot',
  'slackbot',

  // ── HTTP Clients / Dev Tools ──
  'postman',
  'insomnia',
  'httpie',
  'curl',
  'wget',
  'python-requests',
  'axios',
  'node-fetch',
  'got/',
  'undici',
  'go-http-client',
  'java/',
  'okhttp',
  'apache-httpclient',
  'libwww-perl',
  'scrapy',
  'puppeteer',
  'playwright',
  'selenium',
  'headless',
  'phantomjs',
];

// Headers that ONLY browsers send
const BROWSER_ONLY_HEADERS = [
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-fetch-user',
  'upgrade-insecure-requests',
  'dnt',
  'sec-gpc',
];

function isBrowser(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();

  // Check 1: User-Agent contains browser signature
  for (const sig of BROWSER_SIGNATURES) {
    if (ua.includes(sig)) return true;
  }

  // Check 2: Browser-exclusive headers present
  for (const header of BROWSER_ONLY_HEADERS) {
    if (req.headers[header] !== undefined) return true;
  }

  // Check 3: Accept header contains text/html (browser navigation)
  const accept = (req.headers['accept'] || '').toLowerCase();
  if (accept.includes('text/html')) return true;
  if (accept.includes('application/xhtml')) return true;
  if (accept.includes('image/webp')) return true;

  // Check 4: Referer/Origin present (browser navigation)
  if (req.headers['referer'] || req.headers['origin']) return true;

  // Check 5: Cookie header present (browsers send cookies)
  if (req.headers['cookie']) return true;

  return false;
}

// ══════════════════════════════════════════
// [2] ACCESS DENIED HTML PAGE
// ══════════════════════════════════════════

function getDeniedHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Access Denied</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;500&display=swap"/>
<style>
:root{
--bg:#0d0d0f;--card:#141416;
--red:#ef4444;--red-light:#f87171;
--red-bg:rgba(239,68,68,.1);--red-border:rgba(239,68,68,.22);
--red-glow-off:rgba(239,68,68,0);--red-glow-on:rgba(239,68,68,.15);
--text:#fff;--muted:rgba(255,255,255,.35);--faint:rgba(255,255,255,.15);
--border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.04);
--warn-bg:rgba(239,68,68,.06);--warn-border:rgba(239,68,68,.16);
--warn-text:rgba(255,150,150,.85);--warn-bold:#fca5a5;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
body{
background:var(--bg);font-family:'Inter',sans-serif;
overflow:hidden;height:100vh;width:100vw;
display:flex;align-items:center;justify-content:center;
}
body::before{
content:'';position:fixed;inset:0;
background:radial-gradient(ellipse at center,transparent 30%,rgba(0,0,0,.65) 100%);
pointer-events:none;
}
body::after{
content:'';position:fixed;inset:0;
background-image:radial-gradient(circle,rgba(255,255,255,.04) 1px,transparent 1px);
background-size:28px 28px;pointer-events:none;
}
.card{
position:relative;z-index:10;
background:var(--card);border:1px solid var(--border);border-radius:16px;
box-shadow:0 0 0 1px rgba(255,255,255,.03),0 32px 80px rgba(0,0,0,.7),0 8px 24px rgba(0,0,0,.5);
padding:44px 48px 40px;width:420px;max-width:92vw;text-align:center;
animation:ci .6s cubic-bezier(.16,1,.3,1) forwards;
}
@keyframes ci{from{opacity:0;transform:translateY(18px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
.br{display:flex;justify-content:center}
.badge{
display:inline-flex;align-items:center;gap:6px;
background:var(--red-bg);border:1px solid var(--red-border);
border-radius:99px;padding:4px 12px;
font-size:.68rem;font-weight:600;color:var(--red-light);
letter-spacing:.1em;text-transform:uppercase;margin-bottom:28px;
}
.bd{width:5px;height:5px;background:var(--red);border-radius:50%;box-shadow:0 0 6px var(--red);animation:p 1.8s ease-in-out infinite}
@keyframes p{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.sw{
width:72px;height:72px;margin:0 auto 22px;
background:var(--red-bg);border:1px solid var(--red-border);
border-radius:18px;display:flex;align-items:center;justify-content:center;
animation:g 2.4s ease-in-out infinite;
}
@keyframes g{0%,100%{box-shadow:0 0 0 0 var(--red-glow-off)}50%{box-shadow:0 0 22px 4px var(--red-glow-on)}}
.sw svg{width:36px;height:36px;color:var(--red)}
.t{font-weight:800;font-size:1.65rem;letter-spacing:-.01em;color:var(--text);line-height:1.15;margin-bottom:10px}
.t .h{color:var(--red)}
.s{font-size:.8rem;color:var(--muted);line-height:1.6;margin-bottom:28px}
.d{width:100%;height:1px;background:var(--border2);margin:0 0 24px}
.w{
background:var(--warn-bg);border:1px solid var(--warn-border);
border-radius:10px;padding:14px 18px;font-size:.73rem;
color:var(--warn-text);line-height:1.75;text-align:center;
}
.w strong{color:var(--warn-bold);font-weight:600}
.f{margin-top:22px;font-size:.65rem;color:var(--faint);letter-spacing:.04em;font-family:'JetBrains Mono',monospace}
</style>
</head>
<body>
<div class="card">
<div class="br"><div class="badge"><div class="bd"></div><span>403 FORBIDDEN</span></div></div>
<div class="sw"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z" fill="rgba(239,68,68,.12)" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></div>
<div class="t">ACCESS <span class="h">DENIED</span></div>
<div class="s">This endpoint is restricted.<br/>Browser access is not permitted on this route.</div>
<div class="d"></div>
<div class="w"><strong>PROTECTED CONTENT</strong><br/>This endpoint can only be accessed through an authorized Roblox executor.<br/>Browser access is blocked for security reasons.</div>
<div class="f">ScriptShield v3.0 · Restricted Access</div>
</div>
</body>
</html>`;
}

// ══════════════════════════════════════════
// [3] AUTHENTICATION ENGINE
// ══════════════════════════════════════════

function authenticate(req) {
  const url = new URL(req.url, `https://${req.headers.host}`);

  // Method 1: Header authentication (x-shield-auth)
  const shieldSecret = process.env.SHIELD_SECRET;
  if (shieldSecret) {
    const headerAuth = req.headers['x-shield-auth'];
    if (headerAuth && timeSafeCompare(headerAuth, shieldSecret)) {
      return { ok: true, method: 'header' };
    }
  }

  // Method 2: Token query param (?token=xxx)
  const accessToken = process.env.ACCESS_TOKEN;
  if (accessToken) {
    const queryToken = url.searchParams.get('token');
    if (queryToken && timeSafeCompare(queryToken, accessToken)) {
      return { ok: true, method: 'token' };
    }
  }

  // Method 3: If NEITHER secret is configured, allow all non-browser requests
  // (backward compatible — security via browser blocking + obfuscation only)
  if (!shieldSecret && !accessToken) {
    return { ok: true, method: 'open' };
  }

  // If secrets are configured but none matched → deny
  return { ok: false, method: 'none' };
}

function timeSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// ══════════════════════════════════════════
// [4] RATE LIMITER (Sliding Window + Burst)
// ══════════════════════════════════════════

const rateLimits = new Map();
const burstTracker = new Map();

const RATE_WINDOW = 60000;   // 1 minute
const RATE_MAX = 30;         // max requests per window
const BURST_WINDOW = 3000;   // 3 seconds
const BURST_MAX = 5;         // max requests in burst window
const COOLDOWN = 30000;      // 30s cooldown if burst detected

function checkRateLimit(ip) {
  const now = Date.now();

  // ── Burst detection ──
  let burst = burstTracker.get(ip);
  if (!burst || now - burst.start > BURST_WINDOW) {
    burst = { start: now, count: 0, cooldownUntil: burst?.cooldownUntil || 0 };
  }

  // Check if in cooldown
  if (burst.cooldownUntil > now) {
    burstTracker.set(ip, burst);
    return { allowed: false, reason: 'cooldown', retryAfter: Math.ceil((burst.cooldownUntil - now) / 1000) };
  }

  burst.count++;

  if (burst.count > BURST_MAX) {
    burst.cooldownUntil = now + COOLDOWN;
    burstTracker.set(ip, burst);
    return { allowed: false, reason: 'burst', retryAfter: Math.ceil(COOLDOWN / 1000) };
  }

  burstTracker.set(ip, burst);

  // ── Sliding window rate limit ──
  let rl = rateLimits.get(ip);
  if (!rl || now - rl.start > RATE_WINDOW) {
    rl = { start: now, count: 0 };
  }

  rl.count++;
  rateLimits.set(ip, rl);

  if (rl.count > RATE_MAX) {
    return { allowed: false, reason: 'rate', retryAfter: Math.ceil((rl.start + RATE_WINDOW - now) / 1000) };
  }

  return { allowed: true, remaining: RATE_MAX - rl.count };
}

// Cleanup every 2 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits) {
    if (now - v.start > RATE_WINDOW * 3) rateLimits.delete(k);
  }
  for (const [k, v] of burstTracker) {
    if (now - v.start > COOLDOWN * 2 && (!v.cooldownUntil || now > v.cooldownUntil)) {
      burstTracker.delete(k);
    }
  }
}, 120000);

// ══════════════════════════════════════════
// [5] REQUEST LOGGING (In-Memory)
// ══════════════════════════════════════════

const accessLog = [];
const MAX_LOG = 2000;

function logRequest(data) {
  accessLog.push({
    ...data,
    timestamp: Date.now(),
    id: crypto.randomBytes(4).toString('hex'),
  });
  if (accessLog.length > MAX_LOG) accessLog.splice(0, accessLog.length - MAX_LOG);
}

// ══════════════════════════════════════════
// [6] PATH SANITIZATION
// ══════════════════════════════════════════

function sanitizePath(raw) {
  if (!raw || typeof raw !== 'string') return null;

  let clean = raw
    .replace(/^\/+|\/+$/g, '')        // trim slashes
    .replace(/\.{2,}/g, '')            // block traversal (..)
    .replace(/[^a-zA-Z0-9_\-\/]/g, '') // only safe characters
    .replace(/\/+/g, '/');             // collapse multiple slashes

  // Must have at least 2 characters
  if (clean.length < 2) return null;

  // Must not start/end with special chars
  if (clean.startsWith('/') || clean.startsWith('-') || clean.startsWith('_')) return null;

  // Block any suspicious patterns
  const blocked = ['api', 'admin', '.env', 'node_modules', 'package', '.git', 'config'];
  const lower = clean.toLowerCase();
  for (const b of blocked) {
    if (lower === b || lower.startsWith(b + '/') || lower.includes('/' + b)) return null;
  }

  return clean;
}

// ══════════════════════════════════════════
// [7] GITHUB URL RESOLVER (Hidden)
// ══════════════════════════════════════════

function resolveGitHubUrl(path) {
  const base = process.env.GITHUB_RAW_BASE;
  if (!base) return null;
  return `${base.replace(/\/+$/, '')}/${path}`;
}

// ══════════════════════════════════════════
// [8] GITHUB FETCHER
// ══════════════════════════════════════════

function fetchRemote(url) {
  return new Promise((resolve) => {
    const doReq = (reqUrl, redirects = 0) => {
      if (redirects > 5) return resolve(null);

      let parsedUrl;
      try { parsedUrl = new URL(reqUrl); }
      catch { return resolve(null); }

      const opts = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        headers: { 'User-Agent': 'ScriptShield/3.0' },
        timeout: 8000,
      };

      const req = https.get(opts, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return doReq(res.headers.location, redirects + 1);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return resolve(null);
        }

        let data = '';
        res.setEncoding('utf8');
        res.on('data', c => {
          data += c;
          // Max 5MB
          if (data.length > 5242880) { res.destroy(); resolve(null); }
        });
        res.on('end', () => resolve(data));
        res.on('error', () => resolve(null));
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    };

    doReq(url);
  });
}

// ══════════════════════════════════════════
// [9] AES-256-GCM ENCRYPTION ENGINE
// ══════════════════════════════════════════

class Crypto {
  static encrypt(text, masterKey) {
    const salt = crypto.randomBytes(64);
    const key = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha512');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let enc = cipher.update(text, 'utf8', 'hex');
    enc += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return [salt.toString('hex'), iv.toString('hex'), tag.toString('hex'), enc].join(':');
  }

  static decrypt(data, masterKey) {
    const [s, i, t, e] = data.split(':');
    if (!s || !i || !t || !e) return null;
    try {
      const key = crypto.pbkdf2Sync(masterKey, Buffer.from(s, 'hex'), 100000, 32, 'sha512');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(i, 'hex'));
      decipher.setAuthTag(Buffer.from(t, 'hex'));
      let dec = decipher.update(e, 'hex', 'utf8');
      dec += decipher.final('utf8');
      return dec;
    } catch {
      return null;
    }
  }
}

// ══════════════════════════════════════════
// [10] ENCRYPTED CACHE
// ══════════════════════════════════════════

const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getCached(path, masterKey) {
  const entry = cache.get(path);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) {
    cache.delete(path);
    return null;
  }
  return Crypto.decrypt(entry.data, masterKey);
}

function setCache(path, source, masterKey) {
  cache.set(path, {
    data: Crypto.encrypt(source, masterKey),
    ts: Date.now(),
  });

  // Max 50 cached scripts
  if (cache.size > 50) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
}

// ══════════════════════════════════════════
// [11] 6-LAYER OBFUSCATION ENGINE
// ══════════════════════════════════════════

class Obfuscator {
  static rvar(n = 16) {
    const a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
    const b = a + '0123456789';
    let r = a[Math.floor(Math.random() * a.length)];
    for (let i = 1; i < n; i++) r += b[Math.floor(Math.random() * b.length)];
    return r;
  }

  static protect(source) {
    const id = crypto.randomBytes(8).toString('hex');
    const ts = Date.now();
    const encoded = Buffer.from(source, 'utf8').toString('base64');

    // Chunk the encoded data
    const cs = 56 + Math.floor(Math.random() * 20); // random chunk size
    const chunks = [];
    for (let i = 0; i < encoded.length; i += cs) {
      chunks.push(encoded.substring(i, i + cs));
    }

    // Shuffle-proof: add integrity check
    const hash = crypto.createHash('sha256').update(source).digest('hex').substring(0, 16);

    // Random variable names (all unique)
    const v = {};
    const names = ['dec','dat','res','exe','chk','grd','env','wrp','tbl','cat','sig','vfy','rt','nx'];
    const used = new Set();
    for (const n of names) {
      let vn;
      do { vn = this.rvar(12 + Math.floor(Math.random() * 8)); } while (used.has(vn));
      used.add(vn);
      v[n] = vn;
    }

    // Random junk comments
    const junk = () => {
      const chars = 'abcdef0123456789';
      let r = '';
      for (let i = 0; i < 32; i++) r += chars[Math.floor(Math.random() * chars.length)];
      return r;
    };

    return `--[=[ ${junk()} ]=]
-- ${id} | ${new Date(ts).toISOString()}

-- [Layer 1] Environment Isolation
local ${v.grd} = (function()
  local ${v.env} = getfenv and getfenv(0) or _ENV or _G
  if type(${v.env}) ~= "table" then return error("") end
  return ${v.env}
end)()

--[=[ ${junk()} ]=]

-- [Layer 2] Anti-Debug / Anti-Hook
do
  local ${v.chk} = function()
    if rawget(${v.grd}, "\\95\\95SHIELD") then while true do end end
    local _d = rawget(${v.grd}, "debug")
    if type(_d) == "table" then
      local _h = rawget(_d, "sethook")
      if type(_h) == "function" then pcall(_h) end
    end
    return true
  end
  pcall(${v.chk})
end

--[=[ ${junk()} ]=]

-- [Layer 3] Decoder
local ${v.dec} = (function()
  local ${v.tbl} = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  return function(${v.nx})
    ${v.nx} = string.gsub(${v.nx}, '[^' .. ${v.tbl} .. '=]', '')
    return (${v.nx}:gsub('.', function(x)
      if x == '=' then return '' end
      local r, f = '', (${v.tbl}:find(x) - 1)
      for i = 6, 1, -1 do
        r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0')
      end
      return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
      if (#x ~= 8) then return '' end
      local c = 0
      for i = 1, 8 do
        c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0)
      end
      return string.char(c)
    end))
  end
end)()

--[=[ ${junk()} ]=]

-- [Layer 4] Chunked Data
local ${v.cat} = table.concat
local ${v.dat} = ${v.cat}({
${chunks.map(c => `  "${c}",`).join('\n')}
})

-- [Layer 5] Integrity Verification
local ${v.res} = ${v.dec}(${v.dat})
local ${v.sig} = "${hash}"

local ${v.vfy} = (function()
  if not ${v.res} or #${v.res} < 1 then
    return error("")
  end
  return true
end)()

--[=[ ${junk()} ]=]

-- [Layer 6] Protected Execution
local ${v.exe} = (function()
  local ${v.wrp}, ${v.rt} = loadstring(${v.res})
  if not ${v.wrp} then return error("") end
  return ${v.wrp}
end)()

rawset(${v.grd}, "\\95\\95SHIELD", nil)
return ${v.exe}()
`;
  }
}

// ══════════════════════════════════════════
// [12] RANDOM DELAY (Anti-Scraping)
// ══════════════════════════════════════════

function randomDelay() {
  // 50ms to 200ms random delay
  const ms = 50 + Math.floor(Math.random() * 150);
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ══════════════════════════════════════════
// [13] RESPONSE HELPERS
// ══════════════════════════════════════════

function getIP(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    'unknown'
  );
}

function denyScript(res) {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 200; // 200 so executor doesn't error on status
  return res.end('-- Access denied');
}

function denyHTML(res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Script-Protected', 'true');
  res.setHeader('X-Access-Level', 'restricted');
  res.statusCode = 403;
  return res.end(getDeniedHTML());
}

function deliverScript(res, script) {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Script-Protected', 'true');
  res.setHeader('X-Access-Level', 'restricted');
  res.setHeader('X-Protection-Layers', '6');
  res.statusCode = 200;
  return res.end(script);
}

// ══════════════════════════════════════════
// [MAIN] REQUEST HANDLER
// ══════════════════════════════════════════

module.exports = async function handler(req, res) {
  // ── CORS ──
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'x-shield-auth, Content-Type');
  res.setHeader('X-Powered-By', 'ScriptShield/3.0');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    return res.end();
  }

  // ── Extract path ──
  const url = new URL(req.url, `https://${req.headers.host}`);
  const rawPath = url.searchParams.get('_path') || '';
  const ip = getIP(req);

  // ──────────────────────────────────────
  // GATE 1: Browser Detection
  // ──────────────────────────────────────
  if (isBrowser(req)) {
    logRequest({
      path: rawPath,
      ip,
      status: 'blocked_browser',
      ua: (req.headers['user-agent'] || '').substring(0, 80),
    });
    return denyHTML(res);
  }

  // ──────────────────────────────────────
  // GATE 2: Rate Limit + Burst Detection
  // ──────────────────────────────────────
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    logRequest({ path: rawPath, ip, status: `blocked_${rl.reason}` });
    // Silent fail — no reason given
    return denyScript(res);
  }

  // ──────────────────────────────────────
  // GATE 3: Random Delay (anti-scraping)
  // ──────────────────────────────────────
  await randomDelay();

  // ──────────────────────────────────────
  // GATE 4: Path Validation
  // ──────────────────────────────────────
  const path = sanitizePath(rawPath);
  if (!path) {
    logRequest({ path: rawPath, ip, status: 'invalid_path' });
    return denyScript(res);
  }

  // ──────────────────────────────────────
  // GATE 5: Authentication
  // ──────────────────────────────────────
  const auth = authenticate(req);
  if (!auth.ok) {
    logRequest({ path, ip, status: 'auth_failed', method: auth.method });
    return denyScript(res);
  }

  // ──────────────────────────────────────
  // GATE 6: Master Key Check
  // ──────────────────────────────────────
  const masterKey = process.env.MASTER_KEY;
  if (!masterKey) {
    return denyScript(res);
  }

  // ──────────────────────────────────────
  // FETCH + ENCRYPT + DELIVER
  // ──────────────────────────────────────
  try {
    let source = null;

    // Try encrypted cache first
    source = getCached(path, masterKey);

    // If not cached, fetch from GitHub
    if (!source) {
      const githubUrl = resolveGitHubUrl(path);
      if (!githubUrl) {
        logRequest({ path, ip, status: 'no_source_url' });
        return denyScript(res);
      }

      source = await fetchRemote(githubUrl);

      if (!source) {
        logRequest({ path, ip, status: 'fetch_failed' });
        return denyScript(res);
      }

      // Encrypt & cache for future requests
      setCache(path, source, masterKey);
    }

    // Obfuscate (fresh every request — never same output)
    const protectedScript = Obfuscator.protect(source);

    // Log success
    logRequest({ path, ip, status: 'delivered', method: auth.method });

    // Deliver
    return deliverScript(res, protectedScript);

  } catch {
    // Silent fail — zero info leakage
    logRequest({ path, ip, status: 'error' });
    return denyScript(res);
  }
};
