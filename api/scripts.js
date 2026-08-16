// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v10.4 — Delta-Safe Build
//  Fix: hookfunction kill, GC crash, global nil assign crash
//  Compatible: Delta, Arceus X, Fluxus, KRNL, Hydrogen, Codex
// ══════════════════════════════════════════════════════════════════════════

import crypto from "crypto";
import { LOADERS } from "./loader.js";

// ══════════════════════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════════════════════

const CONFIG = {
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 12,
  },
  suspicion: { blockScore: 12 },
  jitter: { minMs: 35, maxMs: 110 },

  page: {
    title: "Access Denied | Flycer Developments",
    badge: "403 Forbidden",
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

  fonts: {
    body: "'Inter', sans-serif",
    mono: "'JetBrains Mono', monospace",
    url: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
  },
  tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",

  browser: {
    uaKeywords: [
      "mozilla","chrome","safari","firefox","edge","opera","brave",
      "vivaldi","webkit","gecko","trident","msie","headlesschrome",
      "phantomjs","selenium","puppeteer","playwright","curl","wget",
      "httpie","postman","insomnia","axios","python-requests","go-http",
      "java/","libwww","perl","ruby","bot","spider","crawl","googlebot",
      "bingbot","yandex","baidu","facebookexternalhit","twitterbot",
      "discord","telegram","whatsapp","slack",
    ],
    uaAllowlist: ["roblox"],
    blockHeaders: [
      "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform",
      "sec-fetch-dest","sec-fetch-mode","sec-fetch-site",
      "sec-fetch-user","upgrade-insecure-requests",
    ],
  },

  executor: {
    penaltyHeaders: [
      { header: "referer",  score: 3 },
      { header: "referrer", score: 3 },
      { header: "origin",   score: 3 },
      { header: "cookie",   score: 4 },
    ],
    penalties: { emptyUA: 5, shortUA: 3, longUA: 2 },
  },
};

// ══════════════════════════════════════════════════════════════════════════
//  IN-MEMORY STORE
// ══════════════════════════════════════════════════════════════════════════

const rateLimitStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, d] of rateLimitStore) {
    if (now - d.windowStart > CONFIG.rateLimit.windowMs * 2) {
      rateLimitStore.delete(ip);
    }
  }
}, 30_000);

// ══════════════════════════════════════════════════════════════════════════
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════════════════════

function randomHex(n = 10) {
  return crypto.randomBytes(n).toString("hex");
}

function xorEncrypt(plaintext) {
  const key   = Array.from(crypto.randomBytes(16));
  const bytes = Array.from(Buffer.from(plaintext, "utf8"));
  const xored = bytes.map((b, i) => b ^ key[i % key.length]);
  return { xored, key };
}

function luaVar() {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  const l     = chars[Math.floor(Math.random() * 26)];
  const hex   = crypto.randomBytes(3).toString("hex");
  return `_${l}${hex}`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA LOADER BUILDER — DELTA SAFE v10.4
//
//  PERUBAHAN dari v10.3:
//  [1] HAPUS hookfunction sepenuhnya → Delta kill proses saat terdeteksi
//  [2] HAPUS setclipboard=nil / writefile=nil / readfile=nil
//       → assign nil ke C-function global = crash di Delta
//  [3] HAPUS collectgarbage manual
//       → beberapa build Delta crash saat GC dipanggil dari Lua
//  [4] XOR pakai lookup table string.byte trick
//       → jauh lebih ringan, tidak ada loop math berat
//  [5] Semua pcall hanya untuk HttpGet dan loadstring
//  [6] Tidak ada global mutation apapun
// ══════════════════════════════════════════════════════════════════════════

function buildLoader(loaderUrl) {
  // Encrypt URL dengan XOR
  const { xored, key } = xorEncrypt(loaderUrl);

  // Split key jadi 3 bagian untuk mempersulit reverse
  // (tidak ada overhead Lua, hanya untuk mempersulit static analysis)
  const k1 = key.slice(0, 5);
  const k2 = key.slice(5, 11);
  const k3 = key.slice(11, 16);

  // Split data juga jadi 3 chunk
  const chunkSize = Math.ceil(xored.length / 3);
  const d1 = xored.slice(0, chunkSize);
  const d2 = xored.slice(chunkSize, chunkSize * 2);
  const d3 = xored.slice(chunkSize * 2);

  // Random variable names
  const v = {
    k1:  luaVar(), k2: luaVar(), k3: luaVar(),
    d1:  luaVar(), d2: luaVar(), d3: luaVar(),
    key: luaVar(), dat: luaVar(),
    dec: luaVar(), url: luaVar(),
    hg:  luaVar(), ok: luaVar(),
    src: luaVar(), fn: luaVar(),
    i:   luaVar(), r:  luaVar(),
  };

  const j = () => `--[[${randomHex(4)}]]`;

  // Catatan: TIDAK ADA hookfunction, TIDAK ADA GC manual,
  // TIDAK ADA global = nil assignment
  return `${j()}
local ${v.k1}={${k1.join(",")}}
local ${v.k2}={${k2.join(",")}}
local ${v.k3}={${k3.join(",")}}
local ${v.d1}={${d1.join(",")}}
local ${v.d2}={${d2.join(",")}}
local ${v.d3}={${d3.join(",")}}
${j()}
local ${v.key}={}
for ${v.i}=1,#${v.k1} do ${v.key}[${v.i}]=${v.k1}[${v.i}] end
for ${v.i}=1,#${v.k2} do ${v.key}[#${v.k1}+${v.i}]=${v.k2}[${v.i}] end
for ${v.i}=1,#${v.k3} do ${v.key}[#${v.k1}+#${v.k2}+${v.i}]=${v.k3}[${v.i}] end
${v.k1}=nil ${v.k2}=nil ${v.k3}=nil
${j()}
local ${v.dat}={}
local ${v.i}=0
for _,b in ipairs(${v.d1}) do ${v.i}=${v.i}+1;${v.dat}[${v.i}]=b end
for _,b in ipairs(${v.d2}) do ${v.i}=${v.i}+1;${v.dat}[${v.i}]=b end
for _,b in ipairs(${v.d3}) do ${v.i}=${v.i}+1;${v.dat}[${v.i}]=b end
${v.d1}=nil ${v.d2}=nil ${v.d3}=nil
${j()}
local ${v.dec}=function(data,key)
  local ${v.r}={}
  local klen=#key
  for idx=1,#data do
    local a=data[idx]
    local b=key[((idx-1)%klen)+1]
    local res=0
    local pow=1
    while a>0 or b>0 do
      if a%2~=b%2 then res=res+pow end
      a=math.floor(a*0.5)
      b=math.floor(b*0.5)
      pow=pow*2
    end
    ${v.r}[idx]=string.char(res)
  end
  return table.concat(${v.r})
end
${j()}
local ${v.url}=${v.dec}(${v.dat},${v.key})
${v.dat}=nil
${v.key}=nil
${v.dec}=nil
if type(${v.url})~="string" or #${v.url}<8 then
  ${v.url}=nil
  return
end
${j()}
local ${v.hg}=game.HttpGet
local ${v.ok},${v.src}=pcall(function()
  return ${v.hg}(game,${v.url})
end)
${v.url}=nil
${v.hg}=nil
if not ${v.ok} then return end
if type(${v.src})~="string" or #${v.src}<10 then
  ${v.src}=nil
  return
end
${j()}
local ${v.fn}=loadstring(${v.src})
${v.src}=nil
if type(${v.fn})~="function" then return end
${v.fn}()
${j()}`;
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
  if (CONFIG.browser.uaAllowlist.some(k => ua.includes(k))) return false;
  if (CONFIG.browser.uaKeywords.some(k => ua.includes(k))) return true;
  if (CONFIG.browser.blockHeaders.some(h => req.headers[h] !== undefined)) return true;
  const accept = (req.headers["accept"] || "").toLowerCase();
  if (accept.includes("text/html") && accept.includes("application/xhtml")) return true;
  return false;
}

function scoreSuspicion(req) {
  const ua  = req.headers["user-agent"] || "";
  let score = 0;
  if (ua.length === 0)      score += CONFIG.executor.penalties.emptyUA;
  else if (ua.length < 6)   score += CONFIG.executor.penalties.shortUA;
  else if (ua.length > 380) score += CONFIG.executor.penalties.longUA;
  for (const { header, score: s } of CONFIG.executor.penaltyHeaders) {
    if (req.headers[header] !== undefined) score += s;
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
  } else {
    entry.count++;
  }
  rateLimitStore.set(ip, entry);
  if (entry.count > maxRequests) {
    return {
      limited:    true,
      retryAfter: Math.ceil((entry.windowStart + windowMs - now) / 1000),
    };
  }
  return { limited: false };
}

function jitterDelay() {
  const { minMs, maxMs } = CONFIG.jitter;
  return new Promise(r =>
    setTimeout(r, minMs + Math.floor(Math.random() * (maxMs - minMs)))
  );
}

// ══════════════════════════════════════════════════════════════════════════
//  RESPONSE HEADERS
// ══════════════════════════════════════════════════════════════════════════

function applyBaseHeaders(res) {
  res.setHeader("X-Content-Type-Options",    "nosniff");
  res.setHeader("X-Frame-Options",           "DENY");
  res.setHeader("X-Robots-Tag",              "noindex,nofollow,noarchive");
  res.setHeader("Cache-Control",             "no-store,no-cache,must-revalidate,private");
  res.setHeader("Pragma",                    "no-cache");
  res.setHeader("Expires",                   "0");
  res.setHeader("Referrer-Policy",           "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy",   "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("X-Request-Id",              randomHex(8));
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");
}

function applyBlockedCSP(res) {
  res.setHeader("Content-Security-Policy", [
    "default-src 'none'",
    "script-src 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "frame-ancestors 'none'",
  ].join("; "));
}

// ══════════════════════════════════════════════════════════════════════════
//  HTML BLOCKED PAGE
// ══════════════════════════════════════════════════════════════════════════

function buildBlockedPage() {
  const { page: p, fonts: f, tailwind: tw } = CONFIG;
  const sub = p.subtitle.join("<br/>");
  const wrn = p.warning.lines.join("<br/>");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <meta name="robots" content="noindex,nofollow"/>
  <title>${p.title}</title>
  <script src="${tw}"><\/script>
  <link href="${f.url}" rel="stylesheet"/>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0d0d0f;font-family:${f.body};overflow:hidden;height:100vh;width:100vw;display:flex;align-items:center;justify-content:center;-webkit-user-select:none;user-select:none}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse at center,transparent 30%,rgba(0,0,0,.65) 100%)}
    body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:radial-gradient(circle,rgba(255,255,255,.04) 1px,transparent 1px);background-size:28px 28px}
    .card{position:relative;z-index:10;background:#141416;border:1px solid rgba(255,255,255,.07);border-radius:16px;box-shadow:0 0 0 1px rgba(255,255,255,.03),0 32px 80px rgba(0,0,0,.7),0 8px 24px rgba(0,0,0,.5);padding:44px 48px 40px;width:420px;max-width:92vw;animation:ci .6s cubic-bezier(.16,1,.3,1) forwards;text-align:center}
    @keyframes ci{from{opacity:0;transform:translateY(18px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
    .badge{display:inline-flex;align-items:center;gap:6px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.22);border-radius:99px;padding:4px 12px;font-size:.68rem;font-weight:600;color:#f87171;letter-spacing:.1em;text-transform:uppercase;margin-bottom:28px}
    .dot{width:5px;height:5px;background:#ef4444;border-radius:50%;box-shadow:0 0 6px #ef4444;animation:pu 1.8s ease-in-out infinite}
    @keyframes pu{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
    .sh{width:72px;height:72px;margin:0 auto 22px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.18);border-radius:18px;display:flex;align-items:center;justify-content:center;animation:gl 2.4s ease-in-out infinite}
    @keyframes gl{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}50%{box-shadow:0 0 22px 4px rgba(239,68,68,.15)}}
    .sh svg{width:36px;height:36px}
    .ti{font-weight:800;font-size:1.65rem;letter-spacing:-.01em;color:#fff;line-height:1.15;margin-bottom:10px}
    .ti span{color:#ef4444}
    .su{font-size:.8rem;color:rgba(255,255,255,.35);line-height:1.6;margin-bottom:28px}
    .dv{width:100%;height:1px;background:rgba(255,255,255,.06);margin-bottom:24px}
    .wb{background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.16);border-radius:10px;padding:14px 18px;font-size:.73rem;color:rgba(255,150,150,.85);line-height:1.75}
    .wb strong{color:#fca5a5;font-weight:600}
    .ft{margin-top:22px;font-size:.65rem;color:rgba(255,255,255,.15);letter-spacing:.04em;font-family:${f.mono}}
  </style>
</head>
<body oncontextmenu="return false">
  <div class="card">
    <div style="display:flex;justify-content:center">
      <div class="badge"><div class="dot"></div>${p.badge}</div>
    </div>
    <div class="sh">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
              fill="rgba(239,68,68,0.12)" stroke="#ef4444" stroke-width="1.5" stroke-linejoin="round"/>
        <line x1="9" y1="12" x2="11" y2="14" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="11" y1="14" x2="15" y2="10" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="ti">${p.heading.prefix} <span>${p.heading.highlight}</span></div>
    <div class="su">${sub}</div>
    <div class="dv"></div>
    <div class="wb"><strong>${p.warning.bold}</strong><br/>${wrn}</div>
    <div class="ft">${p.footer}</div>
  </div>
  <script>
    document.addEventListener('keydown',function(e){
      if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U'))
        e.preventDefault();
    });
  <\/script>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════════════════
//  ROUTE PARSER
// ══════════════════════════════════════════════════════════════════════════

function parseRoute(req) {
  const path = (req.url || "").split("?")[0].replace(/\/+$/, "");

  const m1 = path.match(/\/loaders\/([^/]+\/[^/]+)$/);
  if (m1) return m1[1];

  const m2 = path.match(/^\/([^/]+\/[^/]+)$/);
  if (m2 && !m2[1].startsWith("api/")) return m2[1];

  try {
    const url     = new URL(path, "http://localhost");
    const version = url.searchParams.get("version");
    const name    = url.searchParams.get("name");
    if (version && name) return `${version}/${name}`;
  } catch {}

  return null;
}

// ══════════════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════════════

function sendBlocked(res) {
  applyBlockedCSP(res);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(buildBlockedPage());
}

// ══════════════════════════════════════════════════════════════════════════
//  MAIN HANDLER
// ══════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  applyBaseHeaders(res);

  // L1: Browser → blocked page
  if (isBrowserRequest(req)) return sendBlocked(res);

  // L2: Method guard
  if (!["GET", "HEAD"].includes(req.method)) {
    res.setHeader("Allow", "GET, HEAD");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(405).end("-- method not allowed");
  }

  // L3: Suspicion
  if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
    await jitterDelay();
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end("-- error");
  }

  // L4: Rate limit
  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (rl.limited) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(429).end("-- rate limited");
  }

  // L5: Route → loader key
  const key = parseRoute(req);
  if (!key) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(404).end("-- not found");
  }

  // L6: Lookup registry
  const entry = LOADERS[key];
  if (!entry) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(404).end("-- loader not found");
  }

  // L7: Active check
  if (entry.active === false) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(403).end("-- loader disabled");
  }

  // L8: HEAD
  if (req.method === "HEAD") {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end();
  }

  await jitterDelay();

  // L9: Build & deliver
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
