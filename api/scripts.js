// ══════════════════════════════════════════════════════════════════════════
//  FLYCER SCRIPTS ENGINE v10.3 — Delta Optimized
//  Fix: Crash di Delta Executor
// ══════════════════════════════════════════════════════════════════════════

import crypto from "crypto";
import { LOADERS } from "./loader.js";

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
    footer: "Flycer Loader · Restricted Access",
  },

  fonts: {
    body: "'Inter', sans-serif",
    mono: "'JetBrains Mono', monospace",
    url: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
  },
  tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",

  browser: {
    uaKeywords: [
      "mozilla","chrome","safari","firefox","edge","opera","brave","vivaldi",
      "webkit","gecko","trident","msie","headlesschrome","phantomjs","selenium",
      "puppeteer","playwright","curl","wget","httpie","postman","insomnia","axios",
      "python-requests","bot","spider","crawl","googlebot"
    ],
    uaAllowlist: ["roblox"],
    blockHeaders: [
      "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform","sec-fetch-dest",
      "sec-fetch-mode","sec-fetch-site","sec-fetch-user","upgrade-insecure-requests"
    ],
  },

  executor: {
    penaltyHeaders: [
      { header: "referer", score: 3 },
      { header: "referrer", score: 3 },
      { header: "origin", score: 3 },
      { header: "cookie", score: 4 },
    ],
    penalties: { emptyUA: 5, shortUA: 3, longUA: 2 },
  },
};

const rateLimitStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, d] of rateLimitStore) {
    if (now - d.windowStart > CONFIG.rateLimit.windowMs * 2) rateLimitStore.delete(ip);
  }
}, 30_000);

// ── Crypto ─────────────────────────────────────────────────────────────
function randomHex(n = 12) {
  return crypto.randomBytes(n).toString("hex");
}

function xorEncrypt(plaintext) {
  const key = Array.from(crypto.randomBytes(16));
  const bytes = Array.from(Buffer.from(plaintext, "utf8"));
  const xored = bytes.map((b, i) => b ^ key[i % key.length]);
  return { xored, key };
}

function luaVar() {
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  return `_${alpha[Math.floor(Math.random()*26)]}${crypto.randomBytes(3).toString("hex")}`;
}

// ── Loader Builder (Delta Optimized) ───────────────────────────────────
function buildLoader(loaderUrl) {
  const { xored, key } = xorEncrypt(loaderUrl);

  const v = {
    data: luaVar(),
    key:  luaVar(),
    xor:  luaVar(),
    dec:  luaVar(),
    url:  luaVar(),
    hg:   luaVar(),
    ok:   luaVar(),
    src:  luaVar(),
    fn:   luaVar(),
    t:    luaVar(),
  };

  const j = () => `--[[${randomHex(5)}]]`;

  return `${j()}
local ${v.t}=tick()
${j()}
-- Anti Hook & Anti Spy
local spy=false
pcall(function()
  if hookfunction then
    local old=game.HttpGet
    hookfunction(game.HttpGet,function(...) spy=true;return old(...) end)
  end
end)
if spy then return end
${j()}
-- Disable dangerous functions
pcall(function() setclipboard=nil end)
pcall(function() writefile=nil end)
pcall(function() readfile=nil end)
${j()}
-- Optimized XOR for Delta & Arceus (FIX CRASH)
local ${v.xor}=function(a,b)
  local res=0
  local p=1
  while a>0 or b>0 do
    local ba=a%2
    local bb=b%2
    if ba~=bb then res=res+p end
    a=math.floor(a/2)
    b=math.floor(b/2)
    p=p*2
  end
  return res
end
${j()}
local ${v.data}={${xored.join(",")}}
local ${v.key}={${key.join(",")}}
if tick()-${v.t}>7 then return end
${j()}
-- Decode Function
local ${v.dec}=function(d,k,xf)
  local out={}
  for i=1,#d do
    out[i]=string.char(xf(d[i],k[((i-1)%#k)+1]))
  end
  return table.concat(out)
end
local ${v.url}=${v.dec}(${v.data},${v.key},${v.xor})
${v.data}=nil
${v.key}=nil
${v.xor}=nil
${v.dec}=nil
${j()}
if type(${v.url})~="string" or #${v.url}<8 then return end
if tick()-${v.t}>14 then return end
${j()}
local ${v.hg}=game.HttpGet
local ${v.ok},${v.src}=pcall(${v.hg},game,${v.url})
${v.url}=nil
${v.hg}=nil
if not ${v.ok} or type(${v.src})~="string" or #${v.src}<10 then return end
local ${v.fn}=loadstring(${v.src})
${v.src}=nil
if type(${v.fn})=="function" then
  ${v.fn}()
end
${v.fn}=nil
pcall(collectgarbage,"collect")
${j()}`;
}

// ── Security Functions (sama seperti sebelumnya, tapi suspicion dinaikkan sedikit) ──
function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"] || "";
  return (fwd.split(",")[0].trim() || req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown")
    .replace(/^::ffff:/, "");
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
  const ua = req.headers["user-agent"] || "";
  let score = 0;
  if (ua.length === 0) score += 5;
  else if (ua.length < 6) score += 4;
  else if (ua.length > 380) score += 3;

  const penalties = CONFIG.executor.penaltyHeaders;
  for (const { header, score: s } of penalties) {
    if (req.headers[header] !== undefined) score += s;
  }
  return score;
}

function checkRateLimit(ip) {
  const now = Date.now();
  const win = CONFIG.rateLimit.windowMs;
  const entry = rateLimitStore.get(ip) || { count: 0, windowStart: now };

  if (now - entry.windowStart > win) {
    entry.count = 1;
    entry.windowStart = now;
  } else {
    entry.count++;
  }
  rateLimitStore.set(ip, entry);

  if (entry.count > CONFIG.rateLimit.maxRequests) {
    return { limited: true, retryAfter: Math.ceil((entry.windowStart + win - now)/1000) };
  }
  return { limited: false };
}

function jitterDelay() {
  const { minMs, maxMs } = CONFIG.jitter;
  return new Promise(r => setTimeout(r, minMs + Math.floor(Math.random() * (maxMs - minMs))));
}

// ── Headers & Blocked Page (sama seperti sebelumnya) ─────────────────────
function applyBaseHeaders(res) { /* ... sama seperti kode sebelumnya ... */ }
function applyBlockedCSP(res) { /* ... sama ... */ }
function buildBlockedPage() { /* ... sama seperti versi sebelumnya ... */ }
function sendBlocked(res) {
  applyBlockedCSP(res);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(buildBlockedPage());
}

function parseRoute(req) {
  const path = (req.url || "").split("?")[0].replace(/\/+$/, "");
  const m = path.match(/\/loaders\/([^/]+\/[^/]+)$/) || path.match(/^\/([^/]+\/[^/]+)$/);
  if (m && !m[1].startsWith("api/")) return m[1];
  return null;
}

// ── Main Handler ───────────────────────────────────────────────────────
export default async function handler(req, res) {
  applyBaseHeaders(res);

  if (isBrowserRequest(req)) return sendBlocked(res);

  if (!["GET", "HEAD"].includes(req.method)) {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).end("-- method not allowed");
  }

  if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
    await jitterDelay();
    return res.status(200).end("-- error");
  }

  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (rl.limited) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).end("-- rate limited");
  }

  const key = parseRoute(req);
  if (!key) return res.status(404).end("-- not found");

  const entry = LOADERS[key];
  if (!entry) return res.status(404).end("-- loader not found");
  if (entry.active === false) return res.status(403).end("-- loader disabled");

  if (req.method === "HEAD") return res.status(200).end();

  await jitterDelay();

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).end(buildLoader(entry.url));
}
