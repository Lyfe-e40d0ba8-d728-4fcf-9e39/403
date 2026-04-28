// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v9.1
//  Handler untuk: /loaders/:version/:name
//  Single-line executor compatible:
//  loadstring(game:HttpGet("https://flycer.my.id/loaders/v2/kyoukara"))()
//
//  Registry → api/loader.js
//  Engine   → api/scripts.js (file ini)
// ══════════════════════════════════════════════════════════════════════════

import crypto          from "crypto";
import { LOADERS }     from "./loader.js";   // ← Import registry dari loader.js

// ══════════════════════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════════════════════

const CONFIG = {

  // ── Secrets — WAJIB SAMA dengan gateway.js ───────────────────────────
  secrets: {
    aesKey:  "Snyw5WNU8dl!2ngSd9701gAAt8y*I6AK",  // EXACTLY 32 chars
    hmacKey: "6dd657e1d66ced538d478ce70d9952c077e6afa326576acc991fb581742a5fe3",
  },

  // ── Rate limit ────────────────────────────────────────────────────────
  rateLimit: {
    windowMs:    60_000,
    maxRequests: 10,
  },

  // ── Suspicion ─────────────────────────────────────────────────────────
  suspicion: { blockScore: 10 },

  // ── Jitter ────────────────────────────────────────────────────────────
  jitter: { minMs: 30, maxMs: 100 },

  // ── Blocked page ──────────────────────────────────────────────────────
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

  // ── Browser detection ─────────────────────────────────────────────────
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

  // ── Executor suspicion ────────────────────────────────────────────────
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
//  CRYPTO
// ══════════════════════════════════════════════════════════════════════════

function randomHex(n = 16) {
  return crypto.randomBytes(n).toString("hex");
}

function aesEncrypt(plaintext) {
  const key = crypto.createHash("sha256").update(CONFIG.secrets.aesKey).digest();
  const iv  = crypto.randomBytes(16);
  const c   = crypto.createCipheriv("aes-256-cbc", key, iv);
  const ct  = Buffer.concat([
    c.update(Buffer.from(plaintext, "utf8")),
    c.final(),
  ]);
  return {
    key: Array.from(key),
    iv:  Array.from(iv),
    ct:  Array.from(ct),
  };
}

function xorLayer(data) {
  const key   = Array.from(crypto.randomBytes(16));
  const xored = data.map((b, i) => b ^ key[i % key.length]);
  return { xored, key };
}

function encryptUrl(url) {
  const { key: ak, iv: aiv, ct } = aesEncrypt(url);

  const { xored: ctX, key: ctK } = xorLayer(ct);
  const { xored: ivX, key: ivK } = xorLayer(aiv);
  const { xored: akX, key: akK } = xorLayer(ak);

  return { ctX, ctK, ivX, ivK, akX, akK };
}

// ══════════════════════════════════════════════════════════════════════════
//  PURE LUA AES-256-CBC
// ══════════════════════════════════════════════════════════════════════════

function getLuaAES() {
  return `local function _AES_D(kb,ib,cb)
local S={99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22}
local Si={} for i=0,255 do Si[S[i+1]]=i end
local function gm(a,b)
local r=0
while b>0 do
if b%2==1 then r=r~a end
local h=a>=128
a=(a*2)%256
if h then a=a~0x1b end
b=math.floor(b/2)
end
return r
end
local function ek(key)
local nk=#key//4
local nr=nk+6
local w={}
for i=0,nk-1 do
w[i]={key[i*4+1],key[i*4+2],key[i*4+3],key[i*4+4]}
end
local rc={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}
for i=nk,(4*(nr+1)-1) do
local t={w[i-1][1],w[i-1][2],w[i-1][3],w[i-1][4]}
if i%nk==0 then
t={S[t[2]+1]~rc[i//nk],S[t[3]+1],S[t[4]+1],S[t[1]+1]}
elseif nk>6 and i%nk==4 then
t={S[t[1]+1],S[t[2]+1],S[t[3]+1],S[t[4]+1]}
end
w[i]={w[i-nk][1]~t[1],w[i-nk][2]~t[2],w[i-nk][3]~t[3],w[i-nk][4]~t[4]}
end
return w,nr
end
local function ark(st,w,r)
for c=0,3 do for row=0,3 do st[row+1][c+1]=st[row+1][c+1]~w[r*4+c][row+1] end end
end
local function isb(st)
for c=0,3 do for r=0,3 do st[r+1][c+1]=Si[st[r+1][c+1]] end end
end
local function isr(st)
local tmp={}
for r=0,3 do tmp[r+1]={} for c=0,3 do tmp[r+1][c+1]=st[r+1][(c-r)%4+1] end end
for r=0,3 do for c=0,3 do st[r+1][c+1]=tmp[r+1][c+1] end end
end
local function imc(st)
for c=0,3 do
local a,b,cc,d=st[1][c+1],st[2][c+1],st[3][c+1],st[4][c+1]
st[1][c+1]=gm(a,14)~gm(b,11)~gm(cc,13)~gm(d,9)
st[2][c+1]=gm(a,9)~gm(b,14)~gm(cc,11)~gm(d,13)
st[3][c+1]=gm(a,13)~gm(b,9)~gm(cc,14)~gm(d,11)
st[4][c+1]=gm(a,11)~gm(b,13)~gm(cc,9)~gm(d,14)
end
end
local function db(blk,w,nr)
local st={{},{},{},{}}
for r=0,3 do for c=0,3 do st[r+1][c+1]=blk[r+c*4+1] end end
ark(st,w,nr)
for rd=nr-1,1,-1 do isr(st) isb(st) ark(st,w,rd) imc(st) end
isr(st) isb(st) ark(st,w,0)
local o={}
for c=0,3 do for r=0,3 do o[r+c*4+1]=st[r+1][c+1] end end
return o
end
local w,nr=ek(kb)
local out={}
local prev={table.unpack(ib)}
for i=1,#cb,16 do
local blk={} for j=0,15 do blk[j+1]=cb[i+j] or 0 end
local dec=db(blk,w,nr)
for j=1,16 do if i+j-1<=#cb then out[#out+1]=dec[j]~prev[j] end end
prev=blk
end
local pad=out[#out] or 0
for _=1,pad do table.remove(out) end
local rs={} for _,b in ipairs(out) do rs[#rs+1]=string.char(b) end
return table.concat(rs)
end`;
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
//  LUA LOADER BUILDER
// ══════════════════════════════════════════════════════════════════════════

function buildLoader(loaderUrl) {
  const { ctX, ctK, ivX, ivK, akX, akK } = encryptUrl(loaderUrl);

  const v = {
    ctX: luaVar(), ctK: luaVar(),
    ivX: luaVar(), ivK: luaVar(),
    akX: luaVar(), akK: luaVar(),
    xfn: luaVar(),
    ct:  luaVar(), iv:  luaVar(), ak:  luaVar(),
    url: luaVar(), hg:  luaVar(),
    ok:  luaVar(), src: luaVar(), fn:  luaVar(),
    t0:  luaVar(), spy: luaVar(),
  };

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
local ${v.xfn}=function(d,k)
local r={}
for i=1,#d do
local a,b=d[i],k[((i-1)%#k)+1]
local o=0
for p=0,7 do
if(math.floor(a/2^p)%2)~=(math.floor(b/2^p)%2)then o=o+2^p end
end
r[i]=o
end
return r
end
${j()}
local ${v.ctX}={${ctX.join(",")}}
local ${v.ctK}={${ctK.join(",")}}
local ${v.ivX}={${ivX.join(",")}}
local ${v.ivK}={${ivK.join(",")}}
local ${v.akX}={${akX.join(",")}}
local ${v.akK}={${akK.join(",")}}
if tick()-${v.t0}>8 then return end
local ${v.ct}=${v.xfn}(${v.ctX},${v.ctK})
local ${v.iv}=${v.xfn}(${v.ivX},${v.ivK})
local ${v.ak}=${v.xfn}(${v.akX},${v.akK})
${v.ctX}=nil ${v.ctK}=nil
${v.ivX}=nil ${v.ivK}=nil
${v.akX}=nil ${v.akK}=nil
${v.xfn}=nil
${j()}
${getLuaAES()}
${j()}
local ${v.url}=_AES_D(${v.ak},${v.iv},${v.ct})
_AES_D=nil
${v.ak}=nil ${v.iv}=nil ${v.ct}=nil
if type(${v.url})~="string"or #${v.url}<10 then ${v.url}=nil return end
if tick()-${v.t0}>20 then ${v.url}=nil return end
${j()}
local ${v.hg}=game.HttpGet
local ${v.ok},${v.src}=pcall(function()
return ${v.hg}(game,${v.url})
end)
${v.url}=nil ${v.hg}=nil
if not ${v.ok} or type(${v.src})~="string"or #${v.src}==0 then
${v.src}=nil return
end
local ${v.fn}=loadstring(${v.src})
${v.src}=nil
if type(${v.fn})~="function" then return end
${v.fn}()
${v.fn}=nil ${v.t0}=nil
collectgarbage("collect")${j()}`;
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
//  Match: /loaders/:version/:name
// ══════════════════════════════════════════════════════════════════════════

function parseRoute(req) {
  const path = (req.url || "").split("?")[0].replace(/\/+$/, "");
  const m    = path.match(/^\/loaders\/([^/]+\/[^/]+)$/);
  if (!m) return null;
  return m[1]; // "v2/kyoukara"
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

  // L6: Registry lookup (dari loader.js)
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

  // L8: Build & deliver encrypted loader
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
