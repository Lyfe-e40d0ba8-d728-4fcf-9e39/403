// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v11.1
//  Fix: Script fitur tidak berjalan (Noclip dll)
//  Security: Base64 + XOR + Substitution Cipher (3-layer)
//  Stability: Zero hookfunction, zero GC, zero global mutation
//  Universal: Delta, Arceus X, Fluxus, Wave, Solara, Hydrogen,
//             Codex, Synapse X, KRNL, Xeno, most mobile executors
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
  const b64 = Buffer.from(str, "utf8").toString("base64");
  return Array.from(Buffer.from(b64, "utf8"));
}

// ── Layer 2: XOR ──────────────────────────────────────────────────────────
function xorEncrypt(bytes, key) {
  return bytes.map((b, i) => b ^ key[i % key.length]);
}

// ── Layer 3: Substitution cipher ─────────────────────────────────────────
function buildSubTable() {
  const tbl = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j  = crypto.randomInt(0, i + 1);
    [tbl[i], tbl[j]] = [tbl[j], tbl[i]];
  }
  const inv = new Array(256);
  tbl.forEach((v, k) => { inv[v] = k; });
  return { fwd: tbl, inv };
}

function subEncrypt(bytes, fwdTable) {
  return bytes.map(b => fwdTable[b]);
}

// ── Full 3-layer encrypt ──────────────────────────────────────────────────
function encryptUrl(url) {
  const xorKey       = randomBytes(16);
  const { fwd, inv } = buildSubTable();
  const layer1       = toBase64Bytes(url);
  const layer2       = xorEncrypt(layer1, xorKey);
  const layer3       = subEncrypt(layer2, fwd);
  return { data: layer3, xorKey, invSub: inv };
}

// ── Lua variable name ─────────────────────────────────────────────────────
function luaVar() {
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  const l     = alpha[Math.floor(Math.random() * 26)];
  return `_${l}${crypto.randomBytes(4).toString("hex")}`;
}

// ── Junk comment ──────────────────────────────────────────────────────────
function j() {
  return `--[[${randomHex(6)}]]`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA BASE64 DECODE
//  Pure Lua 5.1 + Luau compatible, no bit32, no external lib
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
//  LUA ENVIRONMENT PATCH
//
//  Beberapa script menggunakan getscriptname() / getcallingscript()
//  untuk verifikasi. Patch ini memastikan environment bersih dan
//  script target berjalan seolah-olah dipanggil langsung.
//
//  PENTING: Patch ini TIDAK mengubah/memblokir fitur apapun dari
//  script target. Hanya memastikan environment kompatibel.
// ══════════════════════════════════════════════════════════════════════════

function getLuaEnvPatch() {
  return `-- Environment compatibility patch
local _genv = getfenv and getfenv(0) or _G
if not _genv then _genv = _G end`;
}

// ══════════════════════════════════════════════════════════════════════════
//  LUA LOADER BUILDER v11.1
//
//  CRITICAL FIX dari v11.0:
//  - pcall wrapper dihapus saat execute fn()
//    Alasan: pcall membungkus environment baru → beberapa fitur script
//    (terutama yang pakai upvalue / getfenv) tidak bisa akses _G dengan benar
//
//  - fn() dipanggil LANGSUNG tanpa pcall
//    Ini memastikan script target berjalan di environment yang IDENTIK
//    dengan loadstring(game:HttpGet("url"))() langsung
//
//  - Tambah setfenv patch untuk executor yang support getfenv/setfenv
//    Memastikan script target dapat akses environment global penuh
//
//  RULES (Universal & Delta-safe):
//  ✅ Zero hookfunction
//  ✅ Zero collectgarbage manual
//  ✅ Zero global = nil assignment
//  ✅ Zero bit32 / ~ operator / // operator
//  ✅ fn() dipanggil langsung (no pcall wrapper) → fitur script penuh
//  ✅ Environment patch untuk kompatibilitas maksimal
// ══════════════════════════════════════════════════════════════════════════

function buildLoader(loaderUrl) {
  const { data, xorKey, invSub } = encryptUrl(loaderUrl);

  // Split invSub jadi 4 bagian (64 elemen masing-masing)
  const sub1 = invSub.slice(0, 64);
  const sub2 = invSub.slice(64, 128);
  const sub3 = invSub.slice(128, 192);
  const sub4 = invSub.slice(192, 256);

  // Split xorKey jadi 2 bagian
  const xk1 = xorKey.slice(0, 8);
  const xk2 = xorKey.slice(8, 16);

  // Split data jadi chunks (40 elemen per chunk)
  const chunks  = [];
  const chunkSz = 40;
  for (let i = 0; i < data.length; i += chunkSz) {
    chunks.push(data.slice(i, i + chunkSz));
  }

  // Variable names
  const v = {
    s1:  luaVar(), s2: luaVar(), s3: luaVar(), s4: luaVar(),
    st:  luaVar(),
    xk1: luaVar(), xk2: luaVar(), xk: luaVar(),
    chunks: chunks.map(() => luaVar()),
    dat: luaVar(),
    idx: luaVar(),
    tmp: luaVar(),
    res: luaVar(),
    b64: luaVar(),
    url: luaVar(),
    hg:  luaVar(),
    ok:  luaVar(),
    src: luaVar(),
    fn:  luaVar(),
    env: luaVar(),
    aa:  luaVar(),
    bb:  luaVar(),
    r:   luaVar(),
    p:   luaVar(),
    klen: luaVar(),
  };

  const lines = [];

  lines.push(j());

  // ── Part 1: Substitution table ─────────────────────────────────────────
  lines.push(`local ${v.s1}={${sub1.join(",")}}`);
  lines.push(`local ${v.s2}={${sub2.join(",")}}`);
  lines.push(`local ${v.s3}={${sub3.join(",")}}`);
  lines.push(`local ${v.s4}={${sub4.join(",")}}`);
  lines.push(j());
  lines.push(`local ${v.st}={}`);
  lines.push(`for ${v.idx}=1,64 do`);
  lines.push(`  ${v.st}[${v.idx}]=${v.s1}[${v.idx}]`);
  lines.push(`  ${v.st}[64+${v.idx}]=${v.s2}[${v.idx}]`);
  lines.push(`  ${v.st}[128+${v.idx}]=${v.s3}[${v.idx}]`);
  lines.push(`  ${v.st}[192+${v.idx}]=${v.s4}[${v.idx}]`);
  lines.push(`end`);
  lines.push(`${v.s1}=nil;${v.s2}=nil;${v.s3}=nil;${v.s4}=nil`);
  lines.push(j());

  // ── Part 2: XOR key ────────────────────────────────────────────────────
  lines.push(`local ${v.xk1}={${xk1.join(",")}}`);
  lines.push(`local ${v.xk2}={${xk2.join(",")}}`);
  lines.push(`local ${v.xk}={}`);
  lines.push(`for ${v.idx}=1,8 do`);
  lines.push(`  ${v.xk}[${v.idx}]=${v.xk1}[${v.idx}]`);
  lines.push(`  ${v.xk}[8+${v.idx}]=${v.xk2}[${v.idx}]`);
  lines.push(`end`);
  lines.push(`${v.xk1}=nil;${v.xk2}=nil`);
  lines.push(j());

  // ── Part 3: Data chunks ────────────────────────────────────────────────
  chunks.forEach((chunk, ci) => {
    lines.push(`local ${v.chunks[ci]}={${chunk.join(",")}}`);
  });
  lines.push(j());
  lines.push(`local ${v.dat}={}`);
  lines.push(`local ${v.idx}=0`);
  chunks.forEach((_, ci) => {
    lines.push(`for _,b in ipairs(${v.chunks[ci]}) do`);
    lines.push(`  ${v.idx}=${v.idx}+1`);
    lines.push(`  ${v.dat}[${v.idx}]=b`);
    lines.push(`end`);
    lines.push(`${v.chunks[ci]}=nil`);
  });
  lines.push(j());

  // ── Part 4: Decrypt ────────────────────────────────────────────────────

  // Step A: Inverse substitution
  lines.push(`local ${v.tmp}={}`);
  lines.push(`for ${v.idx}=1,#${v.dat} do`);
  lines.push(`  ${v.tmp}[${v.idx}]=${v.st}[${v.dat}[${v.idx}]+1]`);
  lines.push(`end`);
  lines.push(`${v.dat}=nil;${v.st}=nil`);
  lines.push(j());

  // Step B: XOR decode
  // Menggunakan while loop ringan — compatible semua executor
  lines.push(`local ${v.res}={}`);
  lines.push(`local ${v.klen}=#${v.xk}`);
  lines.push(`for ${v.idx}=1,#${v.tmp} do`);
  lines.push(`  local ${v.aa}=${v.tmp}[${v.idx}]`);
  lines.push(`  local ${v.bb}=${v.xk}[((${v.idx}-1)%${v.klen})+1]`);
  lines.push(`  local ${v.r}=0`);
  lines.push(`  local ${v.p}=1`);
  lines.push(`  while ${v.aa}>0 or ${v.bb}>0 do`);
  lines.push(`    if ${v.aa}%2~=${v.bb}%2 then ${v.r}=${v.r}+${v.p} end`);
  lines.push(`    ${v.aa}=${v.aa}-${v.aa}%2`);
  lines.push(`    ${v.bb}=${v.bb}-${v.bb}%2`);
  lines.push(`    ${v.aa}=${v.aa}/2`);
  lines.push(`    ${v.bb}=${v.bb}/2`);
  lines.push(`    ${v.p}=${v.p}*2`);
  lines.push(`  end`);
  lines.push(`  ${v.res}[${v.idx}]=string.char(${v.r})`);
  lines.push(`end`);
  lines.push(`${v.tmp}=nil;${v.xk}=nil`);
  lines.push(j());

  // Step C: table.concat → base64 string
  lines.push(`local ${v.b64}=table.concat(${v.res})`);
  lines.push(`${v.res}=nil`);
  lines.push(j());

  // Step D: Base64 decode → URL
  lines.push(getLuaBase64());
  lines.push(j());
  lines.push(`local ${v.url}=_b64d(${v.b64})`);
  lines.push(`_b64d=nil;${v.b64}=nil`);
  lines.push(j());

  // ── Part 5: Validate URL ───────────────────────────────────────────────
  lines.push(`if type(${v.url})~="string" or #${v.url}<8 then`);
  lines.push(`  ${v.url}=nil`);
  lines.push(`  return`);
  lines.push(`end`);
  lines.push(j());

  // ── Part 6: HttpGet source ─────────────────────────────────────────────
  // TIDAK wrap dengan pcall di sini agar tidak ada overhead env
  lines.push(`local ${v.hg}=game.HttpGet`);
  lines.push(`local ${v.ok},${v.src}=pcall(function()`);
  lines.push(`  return ${v.hg}(game,${v.url})`);
  lines.push(`end)`);
  lines.push(`${v.url}=nil;${v.hg}=nil`);
  lines.push(j());
  lines.push(`if not ${v.ok} then return end`);
  lines.push(`if type(${v.src})~="string" or #${v.src}<10 then`);
  lines.push(`  ${v.src}=nil`);
  lines.push(`  return`);
  lines.push(`end`);
  lines.push(j());

  // ── Part 7: loadstring + execute ──────────────────────────────────────
  // KRITIS: fn() dipanggil LANGSUNG tanpa pcall
  // Ini memastikan environment identik dengan loadstring(...)() langsung
  // Semua fitur script (Noclip, GUI, remote, dll) berjalan penuh
  lines.push(`local ${v.fn}=loadstring(${v.src})`);
  lines.push(`${v.src}=nil`);
  lines.push(`if type(${v.fn})~="function" then return end`);
  lines.push(j());

  // Environment patch: setfenv jika tersedia
  // Ini memastikan script target punya akses ke _G penuh
  lines.push(`pcall(function()`);
  lines.push(`  if setfenv then`);
  lines.push(`    setfenv(${v.fn},getfenv(0))`);
  lines.push(`  end`);
  lines.push(`end)`);
  lines.push(j());

  // Execute langsung — TANPA pcall wrapper
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
  const m1   = path.match(/\/loaders\/([^/]+\/[^/]+)$/);
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
//  HELPER
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

  if (isBrowserRequest(req))                    return sendBlocked(res);

  if (!["GET", "HEAD"].includes(req.method)) {
    res.setHeader("Allow", "GET, HEAD");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(405).end("-- method not allowed");
  }

  if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
    await jitterDelay();
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end("-- error");
  }

  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (rl.limited) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(429).end("-- rate limited");
  }

  const key = parseRoute(req);
  if (!key) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(404).end("-- not found");
  }

  const entry = LOADERS[key];
  if (!entry) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(404).end("-- loader not found");
  }

  if (entry.active === false) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(403).end("-- loader disabled");
  }

  if (req.method === "HEAD") {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).end();
  }

  await jitterDelay();

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
