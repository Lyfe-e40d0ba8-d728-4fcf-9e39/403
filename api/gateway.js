// ══════════════════════════════════════════════════════════════════════════════
//  CONFIG — Edit everything here. Nothing else needs to change.
// ══════════════════════════════════════════════════════════════════════════════

const CONFIG = {

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

  // ── Browser Detection ──
  browser: {
    keywords: ["mozilla", "chrome", "safari", "firefox", "edge"],
    exclude: ["roblox"],
  },

  // ── Rate Limit ──
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 10,
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
//  ENGINE — Do NOT edit below unless you're modifying core behavior.
// ══════════════════════════════════════════════════════════════════════════════

// ── Rate Limit Store ─────────────────────────────────────────────────────────

const rateLimitStore = new Map();

// ── Helpers ──────────────────────────────────────────────────────────────────

function isBrowserRequest(userAgent = "") {
  const ua = userAgent.toLowerCase();
  const isBrowser = CONFIG.browser.keywords.some((k) => ua.includes(k));
  const isExcluded = CONFIG.browser.exclude.some((k) => ua.includes(k));
  return isBrowser && !isExcluded;
}

function getClientIp(req) {
  return (
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

// ── Rate Limiter ─────────────────────────────────────────────────────────────

function isRateLimited(ip) {
  const { windowMs, maxRequests } = CONFIG.rateLimit;
  const now = Date.now();
  const entry = rateLimitStore.get(ip) || { count: 0, start: now };

  if (now - entry.start > windowMs) {
    rateLimitStore.set(ip, { count: 1, start: now });
    return false;
  }

  entry.count += 1;
  rateLimitStore.set(ip, entry);

  return entry.count > maxRequests;
}

// ── Token & Hash ─────────────────────────────────────────────────────────────

function generateToken() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  for (let i = 0; i < 32; i++) {
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

// Simple additive hash — 100% identical behavior in JS and Lua
function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash + str.charCodeAt(i)) % 65536;
  }
  return hash;
}

// ── Loader Builder ────────────────────────────────────────────────────────────

function buildLoaderScript() {
  const token = generateToken();
  const hash  = simpleHash(token);
  const url   = CONFIG.loader.url;

  // Lua script:
  // - Pure arithmetic hash (no bit32, no bitwise — compatible with ALL executors)
  // - game:HttpGet colon syntax (works on PC & Mobile executors)
  // - Nil all sensitive vars after use (anti-reuse)
  // - assert() crashes if token is tampered (anti-edit)
  return [
    `local _t="${token}"`,
    `local _h=${hash}`,
    `local function _v(s)`,
    `  local n=0`,
    `  for i=1,#s do`,
    `    n=(n+string.byte(s,i))%65536`,
    `  end`,
    `  return n`,
    `end`,
    `assert(_v(_t)==_h,"invalid token")`,
    `local _s=game:HttpGet("${url}")`,
    `_t=nil`,
    `_h=nil`,
    `_v=nil`,
    `loadstring(_s)()`,
  ].join("\n");
}

// ── Security Headers ──────────────────────────────────────────────────────────

function applySecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Referrer-Policy", "no-referrer");
}

// ── HTML Template ─────────────────────────────────────────────────────────────

function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;

  const subtitleHtml     = page.subtitle.join("<br/>");
  const warningLinesHtml = page.warning.lines.join("<br/>");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${page.title}</title>
  <script src="${tailwind}"><\/script>
  <link href="${fonts.url}" rel="stylesheet">
  <style>
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
  </style>
</head>
<body>
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
</body>
</html>`;
}

// ── Route Handler ─────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  const userAgent = req.headers["user-agent"] || "";
  const ip        = getClientIp(req);

  // 🔒 Security headers — always applied first
  applySecurityHeaders(res);

  // ⛔ Block browser
  if (isBrowserRequest(userAgent)) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(buildBlockedPage());
  }

  // 🚫 Rate limit
  if (isRateLimited(ip)) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(429).send("-- rate limited, try again later");
  }

  // ⏱ Anti-spam jitter (80–200ms)
  const jitter = 80 + Math.floor(Math.random() * 120);
  await new Promise((r) => setTimeout(r, jitter));

  // 🚀 Deliver secured loader
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildLoaderScript());
}
