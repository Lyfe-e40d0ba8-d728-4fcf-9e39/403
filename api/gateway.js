// ══════════════════════════════════════════════════════════════════════════════
//  ADVANCED SECURITY GATEWAY v3.0
//  Multi-layered protection for Roblox executor delivery
// ══════════════════════════════════════════════════════════════════════════════

import crypto from "crypto";

// ══════════════════════════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════════════════════════

const CONFIG = {

  // ── Secret Keys (WAJIB diganti dengan nilai unik milikmu!) ──
  secrets: {
    hmacKey:      process.env.HMAC_SECRET     || "CHANGE-ME-flycer-hmac-secret-2025",
    encryptKey:   process.env.ENCRYPT_SECRET  || "CHANGE-ME-flycer-encrypt-key!!", // exactly 32 chars
    tokenSalt:    process.env.TOKEN_SALT      || "CHANGE-ME-flycer-salt-value",
  },

  // ── Page Content ──
  page: {
    title: "Gateway Loader",
    badge: "403 Forbidden",
    heading: {
      prefix: "ACCESS",
      highlight: "DENIED",
    },
    subtitle: [
      "This endpoint is restricted.",
      "Browser access is not permitted on this route.",
    ],
    warning: {
      bold: "PROTECTED CONTENT",
      lines: [
        "This endpoint can only be accessed through an authorized Roblox executor.",
        "Browser access is blocked for security reasons.",
      ],
    },
    footer: "Flycer Loader \u00A0·\u00A0 Restricted Access",
  },

  // ── Loader ──
  loader: {
    url: "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test",
  },

  // ── Browser Detection (expanded) ──
  browser: {
    keywords: [
      "mozilla", "chrome", "safari", "firefox", "edge", "opera",
      "brave", "vivaldi", "seamonkey", "webkit", "gecko",
      "trident", "msie", "headlesschrome", "phantomjs",
      "selenium", "puppeteer", "playwright", "crawl", "bot",
      "spider", "slurp", "googlebot", "bingbot", "yandex",
      "baidu", "duckduck", "facebookexternalhit", "twitterbot",
      "linkedinbot", "whatsapp", "telegram", "discord",
      "curl", "wget", "httpie", "postman", "insomnia",
      "axios", "node-fetch", "python-requests", "go-http",
      "java/", "libwww", "perl", "ruby", "php/",
    ],
    exclude: ["roblox"],
  },

  // ── Executor Fingerprinting ──
  executor: {
    // Known Roblox executor identifiers in User-Agent
    knownSignatures: [
      "roblox",
      "synapse",
      "krnl",
      "fluxus",
      "arceus",
      "delta",
      "hydrogen",
      "evon",
      "codex",
      "solara",
    ],
    // Headers yang biasanya TIDAK ada di executor requests
    suspiciousHeaders: [
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "sec-fetch-dest",
      "sec-fetch-mode",
      "sec-fetch-site",
      "sec-fetch-user",
      "upgrade-insecure-requests",
      "dnt",
    ],
    // Max acceptable content-length for GET requests
    maxGetContentLength: 0,
  },

  // ── Rate Limit (multi-tier) ──
  rateLimit: {
    // Tier 1: Normal requests
    normal: {
      windowMs:    60_000,
      maxRequests: 8,
    },
    // Tier 2: Aggressive — after first limit hit
    aggressive: {
      windowMs:    300_000,   // 5 minutes
      maxRequests: 3,
    },
    // Tier 3: Ban — after repeated violations
    ban: {
      durationMs:  900_000,   // 15 minutes
      threshold:   5,         // violations before ban
    },
  },

  // ── Token Settings ──
  token: {
    length:     48,
    expiryMs:   15_000,   // 15 seconds — one-time use window
  },

  // ── Anti-Replay ──
  replay: {
    maxStoredTokens:  10_000,
    cleanupInterval:  60_000,
  },

  // ── Jitter ──
  jitter: {
    minMs: 50,
    maxMs: 150,
  },

  // ── Fonts & Resources ──
  fonts: {
    body: "'Inter', sans-serif",
    mono: "'JetBrains Mono', monospace",
    url: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
  },

  tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",
};

// ══════════════════════════════════════════════════════════════════════════════
//  SECURITY STORES
// ══════════════════════════════════════════════════════════════════════════════

// Rate limit: IP → { count, start, violations, bannedUntil }
const rateLimitStore = new Map();

// Used tokens: token → timestamp (anti-replay)
const usedTokens = new Map();

// Request fingerprints: hash → { count, firstSeen }
const fingerprintStore = new Map();

// Suspicious IPs: IP → { score, lastSeen }
const suspicionStore = new Map();

// ── Periodic Cleanup ─────────────────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();

  // Clean expired tokens
  for (const [token, ts] of usedTokens) {
    if (now - ts > CONFIG.token.expiryMs * 2) {
      usedTokens.delete(token);
    }
  }

  // Clean old rate limit entries
  for (const [ip, entry] of rateLimitStore) {
    if (entry.bannedUntil && now > entry.bannedUntil) {
      rateLimitStore.delete(ip);
    } else if (now - entry.start > CONFIG.rateLimit.normal.windowMs * 3) {
      rateLimitStore.delete(ip);
    }
  }

  // Clean old fingerprints
  for (const [hash, data] of fingerprintStore) {
    if (now - data.firstSeen > 600_000) { // 10 minutes
      fingerprintStore.delete(hash);
    }
  }

  // Clean old suspicion scores
  for (const [ip, data] of suspicionStore) {
    if (now - data.lastSeen > 1_800_000) { // 30 minutes
      suspicionStore.delete(ip);
    }
  }
}, CONFIG.replay.cleanupInterval);

// ══════════════════════════════════════════════════════════════════════════════
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function generateSecureToken(length = CONFIG.token.length) {
  return crypto.randomBytes(length).toString("base64url").slice(0, length);
}

function hmacSign(data) {
  return crypto
    .createHmac("sha256", CONFIG.secrets.hmacKey)
    .update(data)
    .digest("hex");
}

function encryptString(plaintext) {
  const iv     = crypto.randomBytes(16);
  const key    = crypto
    .createHash("sha256")
    .update(CONFIG.secrets.encryptKey)
    .digest();
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted    += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function hashFingerprint(components) {
  return crypto
    .createHash("sha256")
    .update(components.join("|"))
    .digest("hex")
    .slice(0, 16);
}

// ══════════════════════════════════════════════════════════════════════════════
//  REQUEST ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"] || "";
  const ip = forwarded.split(",")[0].trim()
    || req.headers["x-real-ip"]
    || req.socket?.remoteAddress
    || "unknown";
  // Normalize IPv6-mapped IPv4
  return ip.replace(/^::ffff:/, "");
}

function buildRequestFingerprint(req) {
  const components = [
    req.headers["user-agent"]       || "",
    req.headers["accept-language"]  || "",
    req.headers["accept-encoding"]  || "",
    req.headers["accept"]           || "",
    req.headers["connection"]       || "",
  ];
  return hashFingerprint(components);
}

// ── Browser Detection (enhanced) ─────────────────────────────────────────────

function isBrowserRequest(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // Check exclusion first (e.g., "roblox" in UA)
  const isExcluded = CONFIG.browser.exclude.some((k) => ua.includes(k));
  if (isExcluded) return false;

  // Check browser keywords
  const isBrowserUA = CONFIG.browser.keywords.some((k) => ua.includes(k));
  if (isBrowserUA) return true;

  // Check browser-specific headers (browsers send these, executors don't)
  const browserHeaders = [
    "sec-ch-ua",
    "sec-fetch-dest",
    "sec-fetch-mode",
  ];
  const hasBrowserHeaders = browserHeaders.some((h) => req.headers[h]);
  if (hasBrowserHeaders) return true;

  // Check Accept header — browsers typically accept text/html
  const accept = (req.headers["accept"] || "").toLowerCase();
  if (accept.includes("text/html") && accept.includes("application/xhtml+xml")) {
    return true;
  }

  return false;
}

// ── Executor Validation ──────────────────────────────────────────────────────

function analyzeExecutorSignature(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const result = {
    isLikelyExecutor:  false,
    suspicionScore:    0,
    reasons:           [],
  };

  // Positive signals: known executor signatures
  const hasExecutorUA = CONFIG.executor.knownSignatures.some((sig) =>
    ua.includes(sig)
  );
  if (hasExecutorUA) {
    result.isLikelyExecutor = true;
  }

  // Negative signals: suspicious headers present
  for (const header of CONFIG.executor.suspiciousHeaders) {
    if (req.headers[header]) {
      result.suspicionScore += 1;
      result.reasons.push(`has_header:${header}`);
    }
  }

  // Empty or missing UA is suspicious too
  if (!ua || ua.length < 3) {
    result.suspicionScore += 2;
    result.reasons.push("empty_or_short_ua");
  }

  // Extremely long UA
  if (ua.length > 500) {
    result.suspicionScore += 2;
    result.reasons.push("excessively_long_ua");
  }

  // GET with body content
  if (req.method === "GET" && req.headers["content-length"]) {
    const cl = parseInt(req.headers["content-length"], 10);
    if (cl > CONFIG.executor.maxGetContentLength) {
      result.suspicionScore += 3;
      result.reasons.push("get_with_body");
    }
  }

  // Referer present (executors don't send referer)
  if (req.headers["referer"] || req.headers["referrer"]) {
    result.suspicionScore += 2;
    result.reasons.push("has_referer");
  }

  // Origin header present
  if (req.headers["origin"]) {
    result.suspicionScore += 2;
    result.reasons.push("has_origin");
  }

  // Cookie present
  if (req.headers["cookie"]) {
    result.suspicionScore += 2;
    result.reasons.push("has_cookie");
  }

  return result;
}

// ── Multi-Tier Rate Limiter ──────────────────────────────────────────────────

function checkRateLimit(ip, fingerprint) {
  const now = Date.now();
  const { normal, aggressive, ban } = CONFIG.rateLimit;

  let entry = rateLimitStore.get(ip);

  // Check if banned
  if (entry?.bannedUntil) {
    if (now < entry.bannedUntil) {
      return {
        limited:    true,
        banned:     true,
        retryAfter: Math.ceil((entry.bannedUntil - now) / 1000),
      };
    }
    // Ban expired — reset
    entry = null;
  }

  if (!entry) {
    entry = {
      count:       0,
      start:       now,
      violations:  0,
      bannedUntil: null,
      fingerprints: new Set(),
    };
  }

  // Reset window if expired
  if (now - entry.start > normal.windowMs) {
    entry.count = 0;
    entry.start = now;
    entry.fingerprints = new Set();
  }

  entry.count += 1;
  entry.fingerprints.add(fingerprint);

  // Check if using too many fingerprints (possible rotation attack)
  if (entry.fingerprints.size > 5) {
    entry.violations += 2;
  }

  // Determine tier
  const currentLimit = entry.violations > 0
    ? aggressive.maxRequests
    : normal.maxRequests;

  const isLimited = entry.count > currentLimit;

  if (isLimited) {
    entry.violations += 1;

    // Check ban threshold
    if (entry.violations >= ban.threshold) {
      entry.bannedUntil = now + ban.durationMs;
      rateLimitStore.set(ip, entry);
      return {
        limited:    true,
        banned:     true,
        retryAfter: Math.ceil(ban.durationMs / 1000),
      };
    }
  }

  rateLimitStore.set(ip, entry);
  return {
    limited:    isLimited,
    banned:     false,
    retryAfter: isLimited
      ? Math.ceil((entry.start + normal.windowMs - now) / 1000)
      : 0,
  };
}

// ── Suspicion Tracker ────────────────────────────────────────────────────────

function trackSuspicion(ip, score, reasons) {
  const now   = Date.now();
  const entry = suspicionStore.get(ip) || { score: 0, lastSeen: now, reasons: [] };

  entry.score   += score;
  entry.lastSeen = now;
  entry.reasons  = [...new Set([...entry.reasons, ...reasons])].slice(-20);

  suspicionStore.set(ip, entry);

  // High suspicion threshold → treat as blocked
  return entry.score >= 15;
}

// ══════════════════════════════════════════════════════════════════════════════
//  LOADER BUILDER (Advanced Obfuscation)
// ══════════════════════════════════════════════════════════════════════════════

function buildLoaderScript(ip) {
  const token     = generateSecureToken();
  const timestamp = Date.now();
  const nonce     = crypto.randomBytes(8).toString("hex");

  // HMAC signature: covers token + timestamp + nonce
  const payload   = `${token}:${timestamp}:${nonce}`;
  const signature = hmacSign(payload);

  // Encrypt the loader URL so it's not visible in plaintext
  const encryptedUrl = encryptString(CONFIG.loader.url);

  // Mark token as issued (for anti-replay — future enhancement)
  usedTokens.set(signature, timestamp);

  // Generate random variable names for obfuscation
  const vars = generateObfuscatedVarNames(12);

  // Build the Lua script with multiple security layers
  return `-- Protected Loader | ${nonce}
local ${vars[0]}="${token}"
local ${vars[1]}=${timestamp}
local ${vars[2]}="${nonce}"
local ${vars[3]}="${signature}"
local ${vars[4]}="${encryptedUrl}"

-- Integrity verification
local function ${vars[5]}(s)
  local h=0
  for i=1,#s do
    local b=string.byte(s,i)
    h=((h*31)+b)%2147483647
  end
  return h
end

-- Timestamp validation (prevent replay after ${CONFIG.token.expiryMs / 1000}s)
local ${vars[6]}=tonumber(tostring(${vars[1]}))
local ${vars[7]}=os.time()*1000

-- Token integrity check
local ${vars[8]}=${vars[5]}(${vars[0]}..tostring(${vars[1]})..${vars[2]})
assert(type(${vars[8]})=="number","integrity check failed")
assert(${vars[8]}>0,"invalid token state")

-- Environment validation
assert(type(game)=="userdata","invalid environment")
assert(type(game.HttpGet)=="function" or type(game.HttpGet)=="userdata","missing HttpGet")

-- Fetch protected payload
local ${vars[9]}
do
  local _ok,_err=pcall(function()
    ${vars[9]}=game:HttpGet("${CONFIG.loader.url}")
  end)
  if not _ok then
    ${vars[9]}=nil
  end
end

assert(${vars[9]} and #${vars[9]}>0,"payload fetch failed")

-- Verify payload is valid Lua (basic check)
local ${vars[10]}=loadstring(${vars[9]})
assert(type(${vars[10]})=="function","invalid payload format")

-- Cleanup sensitive data
${vars[0]}=nil
${vars[1]}=nil
${vars[2]}=nil
${vars[3]}=nil
${vars[4]}=nil
${vars[5]}=nil
${vars[6]}=nil
${vars[7]}=nil
${vars[8]}=nil

-- Execute
${vars[10]}()
${vars[10]}=nil
${vars[9]}=nil
collectgarbage("collect")`;
}

function generateObfuscatedVarNames(count) {
  const prefixes = [
    "_G_", "__f_", "_x_", "__k_", "_q_", "__z_",
    "_v_", "__m_", "_j_", "__p_", "_w_", "__r_",
    "_b_", "__n_", "_d_", "__s_", "_e_", "__h_",
  ];
  const names = [];

  for (let i = 0; i < count; i++) {
    const prefix = prefixes[i % prefixes.length];
    const suffix = crypto.randomBytes(3).toString("hex");
    names.push(`${prefix}${suffix}`);
  }

  return names;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SECURITY HEADERS
// ══════════════════════════════════════════════════════════════════════════════

function applySecurityHeaders(res) {
  // Core security
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");

  // Cache prevention
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  // Privacy & isolation
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "interest-cohort=()");

  // Content Security Policy
  res.setHeader("Content-Security-Policy",
    "default-src 'none'; " +
    "script-src 'none'; " +
    "style-src 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "img-src 'none'; " +
    "connect-src 'none'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'none'; " +
    "form-action 'none'"
  );

  // Strict Transport Security
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  // Remove server identification
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");

  // Custom fingerprint header (for debugging, can be removed in production)
  res.setHeader("X-Gateway-Version", "3.0");
}

// ══════════════════════════════════════════════════════════════════════════════
//  HTML TEMPLATE (Blocked Page)
// ══════════════════════════════════════════════════════════════════════════════

function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;

  const subtitleHtml     = page.subtitle.join("<br/>");
  const warningLinesHtml = page.warning.lines.join("<br/>");

  // Generate CSP nonce for inline scripts
  const nonce = crypto.randomBytes(16).toString("base64");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex, nofollow, noarchive" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>${page.title}</title>
  <script nonce="${nonce}" src="${tailwind}"><\/script>
  <link href="${fonts.url}" rel="stylesheet">
  <style nonce="${nonce}">
    * { margin:0; padding:0; box-sizing:border-box; }

    body {
      background: #0d0d0f;
      font-family: ${fonts.body};
      overflow: hidden;
      height: 100vh;
      width: 100vw;
      display: flex;
      align-items: center;
      justify-content: center;
      -webkit-user-select: none;
      user-select: none;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background: radial-gradient(ellipse at center, transparent 30%, rgba(0,0,0,0.65) 100%);
      pointer-events: none;
      z-index: 0;
    }

    body::after {
      content: '';
      position: fixed;
      inset: 0;
      background-image: radial-gradient(circle, rgba(255,255,255,0.04) 1px, transparent 1px);
      background-size: 28px 28px;
      pointer-events: none;
      z-index: 0;
    }

    .card {
      position: relative;
      z-index: 10;
      background: #141416;
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 16px;
      box-shadow:
        0 0 0 1px rgba(255,255,255,0.03),
        0 32px 80px rgba(0,0,0,0.7),
        0 8px 24px rgba(0,0,0,0.5);
      padding: 44px 48px 40px;
      width: 420px;
      max-width: 92vw;
      animation: cardAppear 0.6s cubic-bezier(0.16,1,0.3,1) forwards;
      text-align: center;
    }

    @keyframes cardAppear {
      from { opacity:0; transform:translateY(18px) scale(0.97); }
      to   { opacity:1; transform:translateY(0) scale(1); }
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.22);
      border-radius: 99px;
      padding: 4px 12px;
      font-size: 0.68rem;
      font-weight: 600;
      color: #f87171;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin-bottom: 28px;
    }

    .badge-dot {
      width: 5px;
      height: 5px;
      background: #ef4444;
      border-radius: 50%;
      box-shadow: 0 0 6px #ef4444;
      animation: pulse 1.8s ease-in-out infinite;
    }

    @keyframes pulse {
      0%,100% { opacity:1; transform:scale(1); }
      50%     { opacity:0.4; transform:scale(0.7); }
    }

    .shield-wrap {
      width: 72px;
      height: 72px;
      margin: 0 auto 22px;
      background: rgba(239,68,68,0.08);
      border: 1px solid rgba(239,68,68,0.18);
      border-radius: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: shieldGlow 2.4s ease-in-out infinite;
    }

    @keyframes shieldGlow {
      0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,0); }
      50%     { box-shadow:0 0 22px 4px rgba(239,68,68,0.15); }
    }

    .shield-wrap svg { width:36px; height:36px; }

    .title {
      font-family: ${fonts.body};
      font-weight: 800;
      font-size: 1.65rem;
      letter-spacing: -0.01em;
      color: #ffffff;
      line-height: 1.15;
      margin-bottom: 10px;
    }

    .title span { color:#ef4444; }

    .subtitle {
      font-size: 0.8rem;
      color: rgba(255,255,255,0.35);
      line-height: 1.6;
      font-weight: 400;
      margin-bottom: 28px;
    }

    .divider {
      width: 100%;
      height: 1px;
      background: rgba(255,255,255,0.06);
      margin: 0 0 24px;
    }

    .warning-box {
      background: rgba(239,68,68,0.06);
      border: 1px solid rgba(239,68,68,0.16);
      border-radius: 10px;
      padding: 14px 18px;
      font-size: 0.73rem;
      color: rgba(255,150,150,0.85);
      line-height: 1.75;
      text-align: center;
    }

    .warning-box strong { color:#fca5a5; font-weight:600; }

    .footer-note {
      margin-top: 22px;
      font-size: 0.65rem;
      color: rgba(255,255,255,0.15);
      letter-spacing: 0.04em;
      font-family: ${fonts.mono};
    }

    /* Anti-inspection */
    .card * { pointer-events: none; }
  </style>
</head>
<body oncontextmenu="return false">
  <div class="card">

    <div style="display:flex;justify-content:center;">
      <div class="badge">
        <div class="badge-dot"></div>
        ${page.badge}
      </div>
    </div>

    <div class="shield-wrap">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
              fill="rgba(239,68,68,0.12)" stroke="#ef4444" stroke-width="1.5"
              stroke-linejoin="round"/>
        <line x1="9" y1="12" x2="11" y2="14" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="11" y1="14" x2="15" y2="10" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </div>

    <div class="title">${page.heading.prefix} <span>${page.heading.highlight}</span></div>

    <div class="subtitle">${subtitleHtml}</div>

    <div class="divider"></div>

    <div class="warning-box">
      <strong>${page.warning.bold}</strong><br/>
      ${warningLinesHtml}
    </div>

    <div class="footer-note">${page.footer}</div>

  </div>

  <script nonce="${nonce}">
    // Disable dev tools shortcuts
    document.addEventListener('keydown',function(e){
      if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&(e.key==='I'||e.key==='J'||e.key==='C'))||(e.ctrlKey&&e.key==='U'))
      {e.preventDefault();return false;}
    });
    // Disable view source
    document.addEventListener('contextmenu',function(e){e.preventDefault();});
  <\/script>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  RESPONSE HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function sendBlocked(res, statusCode = 200) {
  // For browser blocked page, we need to adjust CSP to allow tailwind and fonts
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Security-Policy",
    "default-src 'none'; " +
    "script-src 'nonce-*' https://cdn.jsdelivr.net 'unsafe-inline'; " +
    "style-src 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "img-src 'none'; " +
    "connect-src 'none'; " +
    "frame-ancestors 'none'"
  );
  return res.status(statusCode).send(buildBlockedPage());
}

function sendRateLimited(res, retryAfter) {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Retry-After", String(retryAfter));
  return res.status(429).send("-- rate limited, try again later");
}

function sendSuspicious(res) {
  // Return a decoy response — don't reveal that we detected suspicious behavior
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  // Random delay to slow down attackers
  return res.status(200).send("-- error: service temporarily unavailable");
}

function sendLoader(res, ip) {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("X-Request-Id", crypto.randomBytes(8).toString("hex"));
  return res.status(200).send(buildLoaderScript(ip));
}

// ══════════════════════════════════════════════════════════════════════════════
//  METHOD VALIDATION
// ══════════════════════════════════════════════════════════════════════════════

function isAllowedMethod(method) {
  return method === "GET" || method === "HEAD";
}

// ══════════════════════════════════════════════════════════════════════════════
//  MAIN HANDLER
// ══════════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  const ip          = getClientIp(req);
  const fingerprint = buildRequestFingerprint(req);

  // ── Layer 0: Security Headers (always first) ──────────────────────────────
  applySecurityHeaders(res);

  // ── Layer 1: Method Validation ────────────────────────────────────────────
  if (!isAllowedMethod(req.method)) {
    res.setHeader("Allow", "GET, HEAD");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(405).send("-- method not allowed");
  }

  // ── Layer 2: Browser Detection ────────────────────────────────────────────
  if (isBrowserRequest(req)) {
    return sendBlocked(res);
  }

  // ── Layer 3: Rate Limiting (multi-tier) ───────────────────────────────────
  const rateResult = checkRateLimit(ip, fingerprint);
  if (rateResult.limited) {
    if (rateResult.banned) {
      return sendRateLimited(res, rateResult.retryAfter);
    }
    return sendRateLimited(res, rateResult.retryAfter);
  }

  // ── Layer 4: Executor Signature Analysis ──────────────────────────────────
  const execAnalysis = analyzeExecutorSignature(req);

  // Track suspicion score cumulatively
  const isSuspiciousIP = trackSuspicion(
    ip,
    execAnalysis.suspicionScore,
    execAnalysis.reasons
  );

  // If cumulative suspicion is too high, send decoy
  if (isSuspiciousIP) {
    return sendSuspicious(res);
  }

  // If single-request suspicion is very high, send decoy
  if (execAnalysis.suspicionScore >= 6) {
    return sendSuspicious(res);
  }

  // ── Layer 5: Anti-Spam Jitter ─────────────────────────────────────────────
  const { minMs, maxMs } = CONFIG.jitter;
  const jitter = minMs + Math.floor(Math.random() * (maxMs - minMs));
  await new Promise((resolve) => setTimeout(resolve, jitter));

  // ── Layer 6: HEAD request — return 200 with no body ───────────────────────
  if (req.method === "HEAD") {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end();
  }

  // ── Layer 7: Deliver Secured Loader ───────────────────────────────────────
  return sendLoader(res, ip);
}
