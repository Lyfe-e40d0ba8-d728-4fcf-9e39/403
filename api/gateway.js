// ══════════════════════════════════════════════════════════════════════════
//  FLYCER GATEWAY v4.1 — Single file, no .env, no Redis
//  Vercel Serverless compatible
// ══════════════════════════════════════════════════════════════════════════

import crypto from "crypto";

// ══════════════════════════════════════════════════════════════════════════
//  CONFIG — Edit only this section
// ══════════════════════════════════════════════════════════════════════════

const CONFIG = {

  // ── Secrets (ganti dengan string random milikmu) ──────────────────────
  secrets: {
    hmacKey:   "f7x2!kLqP#9mVnRt@WdYc8JzUeAsBh3G",   // min 32 chars
    tokenSalt: "Qw!eRtYu@IoPaSdF#gHjKlZxCvBnM1234",   // min 32 chars
  },

  // ── Loader URL ────────────────────────────────────────────────────────
  loader: {
    url: "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test",
  },

  // ── Challenge Settings ────────────────────────────────────────────────
  challenge: {
    expiryMs:  15_000,   // 15 detik
    maxStored: 500,      // max challenge tersimpan di memory
  },

  // ── Rate Limit (in-memory) ────────────────────────────────────────────
  rateLimit: {
    windowMs:    60_000,
    maxRequests: 8,
  },

  // ── Suspicion Threshold ───────────────────────────────────────────────
  suspicion: {
    blockScore: 10,
  },

  // ── Jitter ────────────────────────────────────────────────────────────
  jitter: { minMs: 40, maxMs: 130 },

  // ── Page Content ──────────────────────────────────────────────────────
  page: {
    title:   "Gateway Loader",
    badge:   "403 Forbidden",
    heading: { prefix: "ACCESS", highlight: "DENIED" },
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

  // ── Fonts ─────────────────────────────────────────────────────────────
  fonts: {
    body: "'Inter', sans-serif",
    mono: "'JetBrains Mono', monospace",
    url:  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
  },
  tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",

  // ── Browser Detection ─────────────────────────────────────────────────
  browser: {
    keywords: [
      "mozilla","chrome","safari","firefox","edge","opera",
      "brave","vivaldi","webkit","gecko","trident","msie",
      "headlesschrome","phantomjs","selenium","puppeteer",
      "playwright","curl","wget","httpie","postman","insomnia",
      "axios","python-requests","go-http","java/","libwww",
      "perl","ruby","bot","spider","crawl","googlebot",
      "bingbot","yandex","baidu","facebookexternalhit",
      "twitterbot","discord","telegram","whatsapp","slack",
    ],
    allowlist: ["roblox"],
    browserOnlyHeaders: [
      "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform",
      "sec-fetch-dest","sec-fetch-mode","sec-fetch-site",
      "sec-fetch-user","upgrade-insecure-requests",
    ],
  },

  // ── Executor Suspicion ────────────────────────────────────────────────
  executor: {
    penaltyHeaders: [
      { header: "referer",  score: 3 },
      { header: "referrer", score: 3 },
      { header: "origin",   score: 3 },
      { header: "cookie",   score: 4 },
    ],
    penalties: {
      emptyUA: 5, shortUA: 3, longUA: 2, getWithBody: 5,
    },
  },
};

// ══════════════════════════════════════════════════════════════════════════
//  IN-MEMORY STORES
//  ⚠️  Tidak persistent antar cold-start Vercel — by design.
//      Challenge TTL pendek (15s) membuat ini tetap aman.
// ══════════════════════════════════════════════════════════════════════════

// Map<challenge_id, { nonce, timestamp }>
const challengeStore = new Map();

// Map<ip, { count, windowStart }>
const rateLimitStore = new Map();

// ── Periodic cleanup ──────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();

  for (const [id, data] of challengeStore) {
    if (now - data.timestamp > CONFIG.challenge.expiryMs * 2) {
      challengeStore.delete(id);
    }
  }

  for (const [ip, data] of rateLimitStore) {
    if (now - data.windowStart > CONFIG.rateLimit.windowMs * 2) {
      rateLimitStore.delete(ip);
    }
  }
}, 30_000);

// ══════════════════════════════════════════════════════════════════════════
//  CRYPTO
// ══════════════════════════════════════════════════════════════════════════

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hmacSign(data) {
  return crypto
    .createHmac("sha256", CONFIG.secrets.hmacKey)
    .update(String(data))
    .digest("hex");
}

function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

function buildSignature(nonce, timestamp, challengeId) {
  return hmacSign(`${nonce}:${timestamp}:${challengeId}`);
}

function verifySignature(nonce, timestamp, challengeId, sig) {
  const expected = buildSignature(nonce, timestamp, challengeId);
  return safeCompare(expected, sig);
}

// ══════════════════════════════════════════════════════════════════════════
//  SECURITY HELPERS
// ══════════════════════════════════════════════════════════════════════════

function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"] || "";
  const ip  = fwd.split(",")[0].trim()
    || req.headers["x-real-ip"]
    || req.socket?.remoteAddress
    || "unknown";
  return ip.replace(/^::ffff:/, "").trim();
}

function isBrowserRequest(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // Allowlist — executor yang diizinkan
  if (CONFIG.browser.allowlist.some((k) => ua.includes(k))) return false;

  // UA keyword — cocok = browser/tool
  if (CONFIG.browser.keywords.some((k) => ua.includes(k))) return true;

  // Browser-only security headers
  if (CONFIG.browser.browserOnlyHeaders.some((h) => req.headers[h])) return true;

  // Browser-like Accept header
  const accept = (req.headers["accept"] || "").toLowerCase();
  if (accept.includes("text/html") && accept.includes("application/xhtml")) {
    return true;
  }

  return false;
}

function scoreSuspicion(req) {
  const ua = req.headers["user-agent"] || "";
  const { penaltyHeaders, penalties } = CONFIG.executor;
  let score = 0;

  if (ua.length === 0)        score += penalties.emptyUA;
  else if (ua.length < 5)     score += penalties.shortUA;
  else if (ua.length > 400)   score += penalties.longUA;

  for (const { header, score: s } of penaltyHeaders) {
    if (req.headers[header] !== undefined) score += s;
  }

  if (req.method === "GET") {
    const cl = parseInt(req.headers["content-length"] || "0", 10);
    if (cl > 0) score += penalties.getWithBody;
  }

  return score;
}

function checkRateLimit(ip) {
  const { windowMs, maxRequests } = CONFIG.rateLimit;
  const now   = Date.now();
  const entry = rateLimitStore.get(ip) || { count: 0, windowStart: now };

  if (now - entry.windowStart > windowMs) {
    entry.count       = 1;
    entry.windowStart = now;
    rateLimitStore.set(ip, entry);
    return { limited: false };
  }

  entry.count += 1;
  rateLimitStore.set(ip, entry);

  if (entry.count > maxRequests) {
    const retryAfter = Math.ceil((entry.windowStart + windowMs - now) / 1000);
    return { limited: true, retryAfter };
  }

  return { limited: false };
}

function jitter() {
  const { minMs, maxMs } = CONFIG.jitter;
  const ms = minMs + Math.floor(Math.random() * (maxMs - minMs));
  return new Promise((r) => setTimeout(r, ms));
}

// ══════════════════════════════════════════════════════════════════════════
//  HEADERS
// ══════════════════════════════════════════════════════════════════════════

function applyBaseHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Robots-Tag", "noindex,nofollow,noarchive");
  res.setHeader("Cache-Control", "no-store,no-cache,must-revalidate,private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");
  res.setHeader("X-Request-Id", randomHex(8));
}

function applyBlockedPageCSP(res) {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'unsafe-inline' https://cdn.jsdelivr.net",
      "style-src 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "frame-ancestors 'none'",
    ].join("; ")
  );
}

// ══════════════════════════════════════════════════════════════════════════
//  HTML BLOCKED PAGE
// ══════════════════════════════════════════════════════════════════════════

function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;
  const subtitleHtml     = page.subtitle.join("<br/>");
  const warningLinesHtml = page.warning.lines.join("<br/>");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <meta name="robots" content="noindex,nofollow"/>
  <title>${page.title}</title>
  <script src="${tailwind}"><\/script>
  <link href="${fonts.url}" rel="stylesheet"/>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{
      background:#0d0d0f;font-family:${fonts.body};overflow:hidden;
      height:100vh;width:100vw;display:flex;align-items:center;
      justify-content:center;-webkit-user-select:none;user-select:none;
    }
    body::before{
      content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
      background:radial-gradient(ellipse at center,transparent 30%,rgba(0,0,0,.65) 100%);
    }
    body::after{
      content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
      background-image:radial-gradient(circle,rgba(255,255,255,.04) 1px,transparent 1px);
      background-size:28px 28px;
    }
    .card{
      position:relative;z-index:10;background:#141416;
      border:1px solid rgba(255,255,255,.07);border-radius:16px;
      box-shadow:0 0 0 1px rgba(255,255,255,.03),0 32px 80px rgba(0,0,0,.7),0 8px 24px rgba(0,0,0,.5);
      padding:44px 48px 40px;width:420px;max-width:92vw;
      animation:cardIn .6s cubic-bezier(.16,1,.3,1) forwards;text-align:center;
    }
    @keyframes cardIn{
      from{opacity:0;transform:translateY(18px) scale(.97)}
      to{opacity:1;transform:translateY(0) scale(1)}
    }
    .badge{
      display:inline-flex;align-items:center;gap:6px;
      background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.22);
      border-radius:99px;padding:4px 12px;font-size:.68rem;font-weight:600;
      color:#f87171;letter-spacing:.1em;text-transform:uppercase;margin-bottom:28px;
    }
    .dot{
      width:5px;height:5px;background:#ef4444;border-radius:50%;
      box-shadow:0 0 6px #ef4444;animation:pulse 1.8s ease-in-out infinite;
    }
    @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
    .shield{
      width:72px;height:72px;margin:0 auto 22px;
      background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.18);
      border-radius:18px;display:flex;align-items:center;justify-content:center;
      animation:glow 2.4s ease-in-out infinite;
    }
    @keyframes glow{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}50%{box-shadow:0 0 22px 4px rgba(239,68,68,.15)}}
    .shield svg{width:36px;height:36px}
    .title{font-weight:800;font-size:1.65rem;letter-spacing:-.01em;color:#fff;line-height:1.15;margin-bottom:10px}
    .title span{color:#ef4444}
    .sub{font-size:.8rem;color:rgba(255,255,255,.35);line-height:1.6;margin-bottom:28px}
    .divider{width:100%;height:1px;background:rgba(255,255,255,.06);margin-bottom:24px}
    .warn{
      background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.16);
      border-radius:10px;padding:14px 18px;font-size:.73rem;
      color:rgba(255,150,150,.85);line-height:1.75;
    }
    .warn strong{color:#fca5a5;font-weight:600}
    .foot{margin-top:22px;font-size:.65rem;color:rgba(255,255,255,.15);letter-spacing:.04em;font-family:${fonts.mono}}
  </style>
</head>
<body oncontextmenu="return false">
  <div class="card">
    <div style="display:flex;justify-content:center">
      <div class="badge"><div class="dot"></div>${page.badge}</div>
    </div>
    <div class="shield">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
              fill="rgba(239,68,68,0.12)" stroke="#ef4444" stroke-width="1.5" stroke-linejoin="round"/>
        <line x1="9" y1="12" x2="11" y2="14" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="11" y1="14" x2="15" y2="10" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="title">${page.heading.prefix} <span>${page.heading.highlight}</span></div>
    <div class="sub">${subtitleHtml}</div>
    <div class="divider"></div>
    <div class="warn"><strong>${page.warning.bold}</strong><br/>${warningLinesHtml}</div>
    <div class="foot">${page.footer}</div>
  </div>
  <script>
    document.addEventListener('keydown',e=>{
      if(e.key==='F12'
        ||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))
        ||(e.ctrlKey&&e.key==='U'))
        e.preventDefault();
    });
  <\/script>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA LOADER BUILDER
// ══════════════════════════════════════════════════════════════════════════

function buildLoader() {
  const url = CONFIG.loader.url;

  return `-- Flycer Loader
local _ok, _src = pcall(function()
  return game:HttpGet("${url}")
end)
if not _ok or type(_src) ~= "string" or #_src == 0 then
  return
end
local _fn = loadstring(_src)
if type(_fn) ~= "function" then
  return
end
_ok  = nil
_src = nil
_fn()
_fn  = nil
collectgarbage("collect")`;
}

// ══════════════════════════════════════════════════════════════════════════
//  ROUTE DETECTION
// ══════════════════════════════════════════════════════════════════════════

function getRoute(req) {
  const raw  = req.url || "";
  const path = raw.split("?")[0].replace(/\/+$/, "");

  if (path === "/api/challenge") return "challenge";
  if (path === "/api/gateway" || path === "/flycer") return "gateway";
  return "unknown";
}

// ══════════════════════════════════════════════════════════════════════════
//  BODY PARSER
// ══════════════════════════════════════════════════════════════════════════

async function parseBody(req) {
  if (req.body && typeof req.body === "object") return req.body;

  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      try   { resolve(JSON.parse(raw)); }
      catch { resolve(null); }
    });
    req.on("error", () => resolve(null));
  });
}

// ══════════════════════════════════════════════════════════════════════════
//  SHARED — Browser block response
// ══════════════════════════════════════════════════════════════════════════

function sendBlockedPage(res) {
  applyBlockedPageCSP(res);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(buildBlockedPage());
}

// ══════════════════════════════════════════════════════════════════════════
//  HANDLER — /api/challenge
// ══════════════════════════════════════════════════════════════════════════

async function handleChallenge(req, res) {

  // ── Layer 1: Browser block — SELALU PERTAMA ───────────────────────────
  if (isBrowserRequest(req)) return sendBlockedPage(res);

  // ── Layer 2: Method guard ─────────────────────────────────────────────
  if (!["GET", "HEAD"].includes(req.method)) {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).end("-- method not allowed");
  }

  // ── Layer 3: Suspicion ────────────────────────────────────────────────
  if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
    await jitter();
    return res.status(200).end("-- error");
  }

  // ── Layer 4: Rate limit ───────────────────────────────────────────────
  const ip = getClientIp(req);
  const rl  = checkRateLimit(ip);
  if (rl.limited) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).end("-- rate limited");
  }

  // ── HEAD — tidak perlu body ───────────────────────────────────────────
  if (req.method === "HEAD") return res.status(200).end();

  // ── Trim store jika penuh ─────────────────────────────────────────────
  if (challengeStore.size >= CONFIG.challenge.maxStored) {
    const now = Date.now();
    for (const [id, d] of challengeStore) {
      if (now - d.timestamp > CONFIG.challenge.expiryMs) {
        challengeStore.delete(id);
      }
    }
  }

  await jitter();

  // ── Generate & simpan challenge ───────────────────────────────────────
  const nonce        = randomToken(24);
  const challenge_id = randomHex(16);
  const timestamp    = Date.now();

  challengeStore.set(challenge_id, { nonce, timestamp });
  setTimeout(() => challengeStore.delete(challenge_id), CONFIG.challenge.expiryMs * 2);

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(200).json({ challenge_id, nonce, timestamp });
}

// ══════════════════════════════════════════════════════════════════════════
//  HANDLER — /api/gateway  &  /flycer
// ══════════════════════════════════════════════════════════════════════════

async function handleGateway(req, res) {

  // ── Layer 1: Browser block — SELALU PERTAMA ───────────────────────────
  if (isBrowserRequest(req)) return sendBlockedPage(res);

  res.setHeader("Content-Type", "text/plain; charset=utf-8");

  // ── Layer 2: Method guard ─────────────────────────────────────────────
  if (!["POST", "HEAD"].includes(req.method)) {
    res.setHeader("Allow", "POST, HEAD");
    return res.status(405).end("-- method not allowed");
  }

  // ── Layer 3: Suspicion ────────────────────────────────────────────────
  if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
    await jitter();
    return res.status(200).end("-- error");
  }

  // ── Layer 4: Rate limit ───────────────────────────────────────────────
  const ip = getClientIp(req);
  const rl  = checkRateLimit(ip);
  if (rl.limited) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).end("-- rate limited");
  }

  // ── HEAD — tidak perlu body ───────────────────────────────────────────
  if (req.method === "HEAD") return res.status(200).end();

  // ── Layer 5: Parse body ───────────────────────────────────────────────
  const body = await parseBody(req);
  if (!body) return res.status(400).end("-- bad request");

  const { challenge_id, nonce, timestamp, signature } = body;

  // ── Layer 6: Field presence ───────────────────────────────────────────
  if (!challenge_id || !nonce || !timestamp || !signature) {
    return res.status(400).end("-- missing fields");
  }

  // ── Layer 7: Timestamp type ───────────────────────────────────────────
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || ts <= 0) {
    return res.status(400).end("-- invalid timestamp");
  }

  // ── Layer 8: Challenge lookup ─────────────────────────────────────────
  const stored = challengeStore.get(challenge_id);
  if (!stored) {
    await jitter();
    return res.status(403).end("-- challenge expired");
  }

  // ── Layer 9: Nonce match ──────────────────────────────────────────────
  if (stored.nonce !== nonce) {
    challengeStore.delete(challenge_id);
    await jitter();
    return res.status(403).end("-- invalid nonce");
  }

  // ── Layer 10: Freshness ───────────────────────────────────────────────
  const ageMs = Date.now() - ts;
  if (ageMs < 0 || ageMs > CONFIG.challenge.expiryMs) {
    challengeStore.delete(challenge_id);
    await jitter();
    return res.status(403).end("-- challenge expired");
  }

  // ── Layer 11: HMAC signature (timing-safe) ────────────────────────────
  if (!verifySignature(nonce, ts, challenge_id, signature)) {
    challengeStore.delete(challenge_id);
    await jitter();
    return res.status(403).end("-- invalid signature");
  }

  // ── Layer 12: Consume challenge — true one-time use ───────────────────
  challengeStore.delete(challenge_id);

  await jitter();

  return res.status(200).end(buildLoader());
}

// ══════════════════════════════════════════════════════════════════════════
//  MAIN EXPORT
// ══════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {

  // Security headers — selalu pertama sebelum apapun
  applyBaseHeaders(res);

  const route = getRoute(req);

  if (route === "challenge") return handleChallenge(req, res);
  if (route === "gateway")   return handleGateway(req, res);

  // Unknown route — browser dapat blocked page, lainnya 404
  if (isBrowserRequest(req)) return sendBlockedPage(res);
  return res.status(404).end("-- not found");
}
