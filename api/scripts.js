// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v11.0
//  Security  : Base64 + XOR + Substitution Cipher (3-layer)
//  Stability : Zero hookfunction, zero GC, zero global mutation
//  Weight    : Lightweight — no heavy math, no AES in Lua
//  Universal : Delta, Arceus X, Fluxus, Wave, Solara, Hydrogen,
//              Codex, Synapse X, KRNL, Xeno, and most mobile executors
//
//  Encrypt flow (server):
//    URL → Base64 → XOR(key_A) → Substitution(key_B) → array angka
//
//  Decrypt flow (client Lua):
//    array angka → InvSubstitution(key_B) → XOR(key_A) → Base64 decode → URL
// ══════════════════════════════════════════════════════════════════════════

import crypto from "crypto";
import { LOADERS } from "./loader.js";

// ══════════════════════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════════════════════

const CONFIG = {
  rateLimit: {
    windowMs:    60_000,
    maxRequests: 12,
  },
  suspicion: { blockScore: 12 },
  jitter:    { minMs: 35, maxMs: 110 },

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
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════════════════════

function randomHex(n = 10) {
  return crypto.randomBytes(n).toString("hex");
}

function randomBytes(n) {
  return Array.from(crypto.randomBytes(n));
}

// ── Layer 1: Base64 encode ────────────────────────────────────────────────
function toBase64Bytes(str) {
  // Encode string ke Base64 lalu ambil byte-nya
  const b64 = Buffer.from(str, "utf8").toString("base64");
  return Array.from(Buffer.from(b64, "utf8"));
}

// ── Layer 2: XOR dengan key acak 16 byte ─────────────────────────────────
function xorEncrypt(bytes, key) {
  return bytes.map((b, i) => b ^ key[i % key.length]);
}

// ── Layer 3: Substitution cipher ─────────────────────────────────────────
// Buat tabel substitusi acak untuk 256 nilai byte
// Forward: plainByte → cipherByte
// Inverse: cipherByte → plainByte  (untuk decrypt di Lua)
function buildSubTable() {
  // Fisher-Yates shuffle pada 0-255
  const tbl = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [tbl[i], tbl[j]] = [tbl[j], tbl[i]];
  }
  // inverse table
  const inv = new Array(256);
  tbl.forEach((v, k) => { inv[v] = k; });
  return { fwd: tbl, inv };
}

function subEncrypt(bytes, fwdTable) {
  return bytes.map(b => fwdTable[b]);
}

// ── Full 3-layer encrypt ──────────────────────────────────────────────────
function encryptUrl(url) {
  const xorKey        = randomBytes(16);
  const { fwd, inv }  = buildSubTable();

  const layer1 = toBase64Bytes(url);       // Base64 bytes
  const layer2 = xorEncrypt(layer1, xorKey); // XOR
  const layer3 = subEncrypt(layer2, fwd);    // Substitution

  return {
    data:    layer3,   // Final encrypted byte array
    xorKey,            // 16-byte XOR key
    invSub:  inv,      // 256-byte inverse sub table (untuk Lua decode)
  };
}

// ── Lua variable name generator ───────────────────────────────────────────
function luaVar() {
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const l     = alpha[Math.floor(Math.random() * 26)]; // selalu lowercase awal
  return `_${l}${crypto.randomBytes(4).toString("hex")}`;
}

// ── Junk comment ──────────────────────────────────────────────────────────
function j() {
  return `--[[${randomHex(6)}]]`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA BASE64 DECODE (Pure Lua, Lua 5.1 + Luau compatible)
//  Self-contained, no external library, no bit32
// ══════════════════════════════════════════════════════════════════════════

function getLuaBase64() {
  return `local function _b64d(s)
local b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local t={}
for i=1,#b do t[b:sub(i,i)]=i-1 end
local r={}
local buf=0
local bits=0
for i=1,#s do
local c=s:sub(i,i)
if c~="=" then
local v=t[c]
if v then
buf=buf*64+v
bits=bits+6
if bits>=8 then
bits=bits-8
r[#r+1]=string.char(math.floor(buf/2^bits)%256)
buf=buf%(2^bits)
end
end
end
end
return table.concat(r)
end`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA LOADER BUILDER v11
//
//  Client Decrypt Flow:
//  [1] data[] → InvSubstitution(invSub[]) → xored[]
//  [2] xored[] → XOR(xorKey[]) → base64 bytes → base64 string
//  [3] base64 string → base64 decode → URL string
//  [4] URL → HttpGet → loadstring → execute
//
//  RULES (Delta-safe, Universal):
//  ✅ Zero hookfunction
//  ✅ Zero collectgarbage manual
//  ✅ Zero global = nil assignment
//  ✅ Zero bit32 / ~ operator / // operator
//  ✅ Zero heavy math loop
//  ✅ All operations inside local scope
//  ✅ pcall only on HttpGet dan loadstring
// ══════════════════════════════════════════════════════════════════════════

function buildLoader(loaderUrl) {
  const { data, xorKey, invSub } = encryptUrl(loaderUrl);

  // Split invSub table jadi beberapa bagian
  // agar tidak ada 1 array 256 elemen yang obvious
  const sub1 = invSub.slice(0, 64);
  const sub2 = invSub.slice(64, 128);
  const sub3 = invSub.slice(128, 192);
  const sub4 = invSub.slice(192, 256);

  // Split xorKey jadi 2 bagian
  const xk1 = xorKey.slice(0, 8);
  const xk2 = xorKey.slice(8, 16);

  // Split data jadi beberapa chunk (max 40 elemen per chunk)
  // Ini menghindari array raksasa satu baris yang obvious
  const chunks   = [];
  const chunkSz  = 40;
  for (let i = 0; i < data.length; i += chunkSz) {
    chunks.push(data.slice(i, i + chunkSz));
  }

  // ── Variable names ──
  const v = {
    // Sub table parts
    s1: luaVar(), s2: luaVar(), s3: luaVar(), s4: luaVar(),
    st: luaVar(), // full sub table
    // XOR key parts
    xk1: luaVar(), xk2: luaVar(),
    xk:  luaVar(), // full xor key
    // Data chunks (generated below)
    chunks: chunks.map(() => luaVar()),
    dat:  luaVar(), // full data array
    // Working vars
    idx:  luaVar(),
    tmp:  luaVar(),
    res:  luaVar(),
    url:  luaVar(),
    hg:   luaVar(),
    ok:   luaVar(),
    src:  luaVar(),
    fn:   luaVar(),
  };

  // ── Build Lua script ──
  const lines = [];

  lines.push(j());

  // ── Part 1: Substitution table assembly ──
  lines.push(`local ${v.s1}={${sub1.join(",")}}`);
  lines.push(`local ${v.s2}={${sub2.join(",")}}`);
  lines.push(`local ${v.s3}={${sub3.join(",")}}`);
  lines.push(`local ${v.s4}={${sub4.join(",")}}`);
  lines.push(j());

  // Gabung jadi satu table
  lines.push(`local ${v.st}={}`);
  lines.push(`for ${v.idx}=1,#${v.s1} do ${v.st}[${v.idx}]=${v.s1}[${v.idx}] end`);
  lines.push(`for ${v.idx}=1,#${v.s2} do ${v.st}[64+${v.idx}]=${v.s2}[${v.idx}] end`);
  lines.push(`for ${v.idx}=1,#${v.s3} do ${v.st}[128+${v.idx}]=${v.s3}[${v.idx}] end`);
  lines.push(`for ${v.idx}=1,#${v.s4} do ${v.st}[192+${v.idx}]=${v.s4}[${v.idx}] end`);
  // Hapus parts
  lines.push(`${v.s1}=nil ${v.s2}=nil ${v.s3}=nil ${v.s4}=nil`);
  lines.push(j());

  // ── Part 2: XOR key assembly ──
  lines.push(`local ${v.xk1}={${xk1.join(",")}}`);
  lines.push(`local ${v.xk2}={${xk2.join(",")}}`);
  lines.push(`local ${v.xk}={}`);
  lines.push(`for ${v.idx}=1,8 do ${v.xk}[${v.idx}]=${v.xk1}[${v.idx}] end`);
  lines.push(`for ${v.idx}=1,8 do ${v.xk}[8+${v.idx}]=${v.xk2}[${v.idx}] end`);
  lines.push(`${v.xk1}=nil ${v.xk2}=nil`);
  lines.push(j());

  // ── Part 3: Data chunks ──
  chunks.forEach((chunk, ci) => {
    lines.push(`local ${v.chunks[ci]}={${chunk.join(",")}}`);
  });
  lines.push(j());

  // Gabung semua chunk
  lines.push(`local ${v.dat}={}`);
  lines.push(`local ${v.idx}=0`);
  chunks.forEach((_, ci) => {
    lines.push(`for _,b in ipairs(${v.chunks[ci]}) do ${v.idx}=${v.idx}+1;${v.dat}[${v.idx}]=b end`);
    lines.push(`${v.chunks[ci]}=nil`);
  });
  lines.push(j());

  // ── Part 4: Decrypt ──
  // Step A: InvSub
  lines.push(`local ${v.tmp}={}`);
  lines.push(`for ${v.idx}=1,#${v.dat} do`);
  lines.push(`  local b=${v.dat}[${v.idx}]`);
  lines.push(`  ${v.tmp}[${v.idx}]=${v.st}[b+1]`);  // +1 karena Lua 1-indexed
  lines.push(`end`);
  lines.push(`${v.dat}=nil`);
  lines.push(`${v.st}=nil`);
  lines.push(j());

  // Step B: XOR decode
  lines.push(`local ${v.res}={}`);
  lines.push(`local klen=#${v.xk}`);
  lines.push(`for ${v.idx}=1,#${v.tmp} do`);
  lines.push(`  local a=${v.tmp}[${v.idx}]`);
  lines.push(`  local b=${v.xk}[((${v.idx}-1)%klen)+1]`);
  // XOR tanpa ~ operator, tanpa bit32, tanpa math.floor berat
  lines.push(`  local r=0`);
  lines.push(`  local p=1`);
  lines.push(`  local aa=a`);
  lines.push(`  local bb=b`);
  lines.push(`  while aa>0 or bb>0 do`);
  lines.push(`    if aa%2~=bb%2 then r=r+p end`);
  lines.push(`    aa=aa-aa%2`);   // aa = floor(aa/1)*1 trick (ringan)
  lines.push(`    bb=bb-bb%2`);
  lines.push(`    aa=aa/2`);
  lines.push(`    bb=bb/2`);
  lines.push(`    p=p*2`);
  lines.push(`  end`);
  lines.push(`  ${v.res}[${v.idx}]=string.char(r)`);
  lines.push(`end`);
  lines.push(`${v.tmp}=nil`);
  lines.push(`${v.xk}=nil`);
  lines.push(j());

  // Step C: Gabung chars → base64 string
  lines.push(`local b64str=table.concat(${v.res})`);
  lines.push(`${v.res}=nil`);
  lines.push(j());

  // Step D: Base64 decode → URL
  lines.push(getLuaBase64());
  lines.push(j());
  lines.push(`local ${v.url}=_b64d(b64str)`);
  lines.push(`_b64d=nil`);
  lines.push(`b64str=nil`);
  lines.push(j());

  // ── Part 5: Validate & Execute ──
  lines.push(`if type(${v.url})~="string" or #${v.url}<8 then`);
  lines.push(`  ${v.url}=nil`);
  lines.push(`  return`);
  lines.push(`end`);
  lines.push(j());

  lines.push(`local ${v.hg}=game.HttpGet`);
  lines.push(`local ${v.ok},${v.src}=pcall(function()`);
  lines.push(`  return ${v.hg}(game,${v.url})`);
  lines.push(`end)`);
  lines.push(`${v.url}=nil`);
  lines.push(`${v.hg}=nil`);
  lines.push(j());

  lines.push(`if not ${v.ok} then return end`);
  lines.push(`if type(${v.src})~="string" or #${v.src}<10 then`);
  lines.push(`  ${v.src}=nil`);
  lines.push(`  return`);
  lines.push(`end`);
  lines.push(j());

  lines.push(`local ${v.fn}=loadstring(${v.src})`);
  lines.push(`${v.src}=nil`);
  lines.push(`if type(${v.fn})~="function" then return end`);
  lines.push(`${v.fn}()`);
  lines.push(`${v.fn}=nil`);
  lines.push(j());

  return lines.join("\n");
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
    const u       = new URL(path, "http://localhost");
    const version = u.searchParams.get("version");
    const name    = u.searchParams.get("name");
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

  // L1: Browser
  if (isBrowserRequest(req)) return sendBlocked(res);

  // L2: Method
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

  // L5: Route
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

  // L7: Active
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

  // L9: Deliver
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
