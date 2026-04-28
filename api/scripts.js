// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v10.0 — Universal XOR-Only
//  Compatible: ALL executors (mobile + PC, Lua 5.1 / Luau)
//
//  loadstring(game:HttpGet("https://flycer.my.id/loaders/v2/kyoukara"))()
//
//  Registry → api/loader.js
//  Engine   → api/scripts.js (file ini)
//
//  NO ~ operator, NO // operator, NO bit32, NO external library
// ══════════════════════════════════════════════════════════════════════════

import crypto          from "crypto";
import { LOADERS }     from "./loader.js";

// ══════════════════════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════════════════════

const CONFIG = {

  secrets: {
    aesKey:  "thV#e9Nusf0pF4L5wy7arEF$MefV46L8",
    hmacKey: "62631413ec3e236a82d809d31bb4d666f43d2fee207c599320786d8cfad18b71",
  },

  rateLimit: {
    windowMs:    60_000,
    maxRequests: 10,
  },

  suspicion: { blockScore: 10 },

  jitter: { minMs: 30, maxMs: 100 },

  page: {
    title:   "Gateway Loader",
    badge:   "403 Forbidden",
    heading: { prefix: "ACCESS", highlight: "DENIED" },
    subtitle: [
      "This endpoint is restricted.",
      "Browser access is not permitted on this route.",
    ],
    warning: {
      bold:  "PROTECTED CONTENT",
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
    url:  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
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
//  CRYPTO — SERVER SIDE
// ══════════════════════════════════════════════════════════════════════════

function randomHex(n = 16) {
  return crypto.randomBytes(n).toString("hex");
}

// ── Server-side AES transform (internal obfuscation, not sent to client) ─

function serverAesTransform(plaintext) {
  const key = crypto.createHash("sha256").update(CONFIG.secrets.aesKey).digest();
  const iv  = crypto.randomBytes(16);

  // Encrypt
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final(),
  ]);

  // Immediately decrypt (AES is server-side transform only)
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

// ── XOR encrypt for client (Lua-compatible) ──────────────────────────────

function xorEncryptForClient(plaintext) {
  const key      = Array.from(crypto.randomBytes(16));
  const bytes    = Array.from(Buffer.from(plaintext, "utf8"));
  const xored    = bytes.map((b, i) => b ^ key[i % key.length]);

  // Split key into 2 halves (extra obfuscation)
  const keyHalf1 = key.slice(0, 8);
  const keyHalf2 = key.slice(8, 16);

  return { xored, keyHalf1, keyHalf2 };
}

// ══════════════════════════════════════════════════════════════════════════
//  RANDOM LUA VARIABLE NAME
// ══════════════════════════════════════════════════════════════════════════

function luaVar() {
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  const l     = alpha[Math.floor(Math.random() * 26)];
  return `_${l}${crypto.randomBytes(3).toString("hex")}`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA LOADER BUILDER — UNIVERSAL XOR-ONLY
//
//  ✅ NO ~ operator         (uses arithmetic XOR via math.floor)
//  ✅ NO // operator        (uses math.floor(a/b))
//  ✅ NO bit32 library      (pure arithmetic)
//  ✅ NO external library   (self-contained)
//  ✅ Compatible: Lua 5.1, Luau, ALL executors
//
//  Every request produces a UNIQUE script:
//  ✓ Different XOR keys (random per request)
//  ✓ Different variable names (random per request)
//  ✓ Different junk comments (random per request)
//  ✓ No readable URL anywhere in the script
//  ✓ Key split into 2 halves (harder to extract)
//
//  Client flow:
//  Reassemble key → XOR decrypt → URL string → HttpGet → loadstring
// ══════════════════════════════════════════════════════════════════════════

function buildLoader(loaderUrl) {

  // Server-side AES transform (internal obfuscation)
  const transformed = serverAesTransform(loaderUrl);

  // XOR encrypt for client delivery
  const { xored, keyHalf1, keyHalf2 } = xorEncryptForClient(transformed);

  // Random variable names — unique every request
  const v = {
    d:    luaVar(),   // xorData array
    k1:   luaVar(),   // key half 1
    k2:   luaVar(),   // key half 2
    k:    luaVar(),   // reassembled full key
    xfn:  luaVar(),   // xor function
    bfn:  luaVar(),   // byte-to-string function
    url:  luaVar(),   // decrypted url
    hg:   luaVar(),   // HttpGet ref
    ok:   luaVar(),   // pcall success
    src:  luaVar(),   // fetched source
    fn:   luaVar(),   // loadstring result
    t0:   luaVar(),   // tick start
    spy:  luaVar(),   // anti-spy flag
  };

  // Junk comments — unique hash every request
  const j = () => `--[[${randomHex(6)}]]`;

  return `${j()}
local ${v.t0}=tick()
local ${v.spy}=false
${j()}
pcall(function()
if type(hookfunction)=="function" then
local _o=game.HttpGet
hookfunction(game.HttpGet,function(...)
${v.spy}=true
return _o(...)
end)
end
end)
if ${v.spy} then return end
pcall(function() if type(setclipboard)=="function" then setclipboard=function()end end end)
pcall(function() if type(writefile)=="function" then writefile=function()end end end)
pcall(function() if type(readfile)=="function" then readfile=function()end end end)
${j()}
local ${v.xfn}=function(a,b)
local o=0
local p=1
for i=0,7 do
local ba=math.floor(a/p)%2
local bb=math.floor(b/p)%2
if ba~=bb then
o=o+p
end
p=p*2
end
return o
end
${j()}
local ${v.d}={${xored.join(",")}}
local ${v.k1}={${keyHalf1.join(",")}}
local ${v.k2}={${keyHalf2.join(",")}}
if tick()-${v.t0}>8 then return end
local ${v.k}={}
for i=1,#${v.k1} do ${v.k}[i]=${v.k1}[i] end
for i=1,#${v.k2} do ${v.k}[#${v.k1}+i]=${v.k2}[i] end
${v.k1}=nil
${v.k2}=nil
${j()}
local ${v.bfn}=function(d,k,xf)
local r={}
for i=1,#d do
local ki=((i-1)%#k)+1
r[i]=string.char(xf(d[i],k[ki]))
end
return table.concat(r)
end
local ${v.url}=${v.bfn}(${v.d},${v.k},${v.xfn})
${v.d}=nil
${v.k}=nil
${v.xfn}=nil
${v.bfn}=nil
${j()}
if type(${v.url})~="string" or #${v.url}<10 then
${v.url}=nil
return
end
if tick()-${v.t0}>15 then
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
if not ${v.ok} or type(${v.src})~="string" or #${v.src}==0 then
${v.src}=nil
return
end
local ${v.fn}=loadstring(${v.src})
${v.src}=nil
if type(${v.fn})~="function" then
return
end
${v.fn}()
${v.fn}=nil
${v.t0}=nil
pcall(function()
local ok,_=pcall(collectgarbage,"collect")
if not ok then pcall(gcinfo) end
end)
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
  if (CONFIG.browser.blockHeaders.some(h => req.headers[h])) return true;
  const accept = (req.headers["accept"] || "").toLowerCase();
  if (accept.includes("text/html") && accept.includes("application/xhtml")) return true;
  return false;
}

function scoreSuspicion(req) {
  const ua = req.headers["user-agent"] || "";
  const { penaltyHeaders, penalties } = CONFIG.executor;
  let score = 0;
  if (ua.length === 0)      score += penalties.emptyUA;
  else if (ua.length < 5)   score += penalties.shortUA;
  else if (ua.length > 400) score += penalties.longUA;
  for (const { header, score: s } of penaltyHeaders) {
    if (req.headers[header] !== undefined) score += s;
  }
  return score;
}

function checkRateLimit(ip) {
  const { windowMs, maxRequests } = CONFIG.rateLimit;
  const now = Date.now();
  const e   = rateLimitStore.get(ip) || { count: 0, windowStart: now };
  if (now - e.windowStart > windowMs) {
    e.count = 1; e.windowStart = now;
    rateLimitStore.set(ip, e);
    return { limited: false };
  }
  e.count++;
  rateLimitStore.set(ip, e);
  if (e.count > maxRequests) {
    return {
      limited:    true,
      retryAfter: Math.ceil((e.windowStart + windowMs - now) / 1000),
    };
  }
  return { limited: false };
}

function jitterDelay() {
  const { minMs, maxMs } = CONFIG.jitter;
  return new Promise(r => setTimeout(r, minMs + Math.floor(Math.random() * (maxMs - minMs))));
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
  res.setHeader("X-Request-Id",             randomHex(8));
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
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z" fill="rgba(239,68,68,0.12)" stroke="#ef4444" stroke-width="1.5" stroke-linejoin="round"/>
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
  const raw  = req.url || "";
  const path = raw.split("?")[0].replace(/\/+$/, "");

  const m1 = path.match(/\/loaders\/([^/]+\/[^/]+)$/);
  if (m1) return m1[1];

  const m2 = path.match(/\/([^/]+\/[^/]+)$/);
  if (m2 && !m2[1].startsWith("api/")) return m2[1];

  try {
    const url     = new URL(raw, "http://localhost");
    const version = url.searchParams.get("version");
    const name    = url.searchParams.get("name");
    if (version && name) return `${version}/${name}`;
  } catch {}

  return null;
}

// ══════════════════════════════════════════════════════════════════════════
//  SHARED
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

  // L5: Route parse
  const key = parseRoute(req);
  if (!key) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(404).end("-- not found");
  }

  // L6: Registry lookup
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

  // HEAD
  if (req.method === "HEAD") {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end();
  }

  await jitterDelay();

  // L8: Build & deliver
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
