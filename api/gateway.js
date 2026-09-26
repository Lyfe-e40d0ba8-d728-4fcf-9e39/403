import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
    LOADERS
} from "./loader.js";

//  CONFIGS
const CONFIG = {
    secrets: {
        hmacKey: process.env.HMAC_KEY || "6dd657e1d66ced538d478ce70d9952c077e6afa326576acc991fb581742a5fe3",
    },
    challenge: {
        expiryMs: 15_000,
        maxStored: 500,
    },
    rateLimit: {
        windowMs: 60_000,
        maxRequests: 8,
    },
    suspicion: {
        blockScore: 10,
    },
    jitter: {
        minMs: 40,
        maxMs: 130
    },
    page: {
        title: "Access Denied | Flycer Developments",
        badge: "403 Forbidden",
        heading: {
            prefix: "ACCESS",
            highlight: "DENIED"
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
            "mozilla", "chrome", "safari", "firefox", "edge", "opera", "brave",
            "vivaldi", "webkit", "gecko", "trident", "msie", "headlesschrome",
            "phantomjs", "selenium", "puppeteer", "playwright", "curl", "wget",
            "httpie", "postman", "insomnia", "axios", "python-requests", "go-http",
            "java/", "libwww", "perl", "ruby", "bot", "spider", "crawl",
            "googlebot", "bingbot", "yandex", "baidu", "facebookexternalhit",
            "twitterbot", "discord", "telegram", "whatsapp", "slack",
        ],
        uaAllowlist: ["roblox"],
        blockHeaders: [
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            "sec-fetch-user", "upgrade-insecure-requests",
        ],
    },
    executor: {
        penaltyHeaders: [{
                header: "referer",
                score: 3
            },
            {
                header: "referrer",
                score: 3
            },
            {
                header: "origin",
                score: 3
            },
            {
                header: "cookie",
                score: 4
            },
        ],
        penalties: {
            emptyUA: 5,
            shortUA: 3,
            longUA: 2,
            getWithBody: 5,
        },
    },
};

const challengeStore = new Map();
const rateLimitStore = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [id, d] of challengeStore) {
        if (now - d.timestamp > CONFIG.challenge.expiryMs * 2) challengeStore.delete(id);
    }
    for (const [ip, d] of rateLimitStore) {
        if (now - d.windowStart > CONFIG.rateLimit.windowMs * 2) rateLimitStore.delete(ip);
    }
}, 30_000);

function randomHex(n = 16) {
    return crypto.randomBytes(n).toString("hex");
}

function randomToken(n = 24) {
    return crypto.randomBytes(n).toString("base64url");
}

function hmacSign(data) {
    return crypto
        .createHmac("sha256", CONFIG.secrets.hmacKey)
        .update(String(data))
        .digest("hex");
}

function safeCompare(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

function buildSignature(nonce, ts, id) {
    return hmacSign(`${nonce}:${ts}:${id}`);
}

function verifySignature(nonce, ts, id, sig) {
    return safeCompare(buildSignature(nonce, ts, id), sig);
}

function buildSubTable() {
    const tbl = Array.from({
        length: 256
    }, (_, i) => i);
    for (let i = 255; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [tbl[i], tbl[j]] = [tbl[j], tbl[i]];
    }
    const inv = new Array(256);
    tbl.forEach((v, k) => {
        inv[v] = k;
    });
    return {
        fwd: tbl,
        inv
    };
}

function encryptPayload(source) {
    const payloadBytes = Array.from(Buffer.from(source, "utf8"));
    const xorKey = crypto.randomBytes(16);
    const {
        fwd,
        inv
    } = buildSubTable();

    const layer1 = payloadBytes.map(b => fwd[b]);
    const layer2 = layer1.map((b, i) => b ^ xorKey[i % xorKey.length]);

    return {
        ciphertext: layer2,
        xorKey: Array.from(xorKey),
        invSub: inv
    };
}

function luaVar() {
    const alpha = "abcdefghijklmnopqrstuvwxyz";
    const l = alpha[Math.floor(Math.random() * 26)];
    return `_${l}${crypto.randomBytes(4).toString("hex")}`;
}

function toLuaEscapedChunks(bytes, varName) {
    const chunkSize = 250;
    const lines = [];
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.slice(i, i + chunkSize);
        const escaped = chunk.map(b => `\\${b}`).join("");
        if (i === 0) {
            lines.push(`local ${varName} = "${escaped}"`);
        } else {
            lines.push(`${varName} = ${varName} .. "${escaped}"`);
        }
    }
    return lines.join("\n");
}

function buildLoader(rawSource) {
    const {
        ciphertext,
        xorKey,
        invSub
    } = encryptPayload(rawSource);

    const v = {
        cipherVar: luaVar(),
        keyVar: luaVar(),
        subVar: luaVar(),
        decryptedVar: luaVar(),
        fnVar: luaVar(),
        decryptFn: luaVar(),
        t0: luaVar(),
        spy: luaVar(),
        _xor: luaVar()
    };

    const cipherCode = toLuaEscapedChunks(ciphertext, v.cipherVar);
    const keyEscaped = xorKey.map(b => `\\${b}`).join("");
    const subEscaped = invSub.map(b => `\\${b}`).join("");

    const jVal = () => `--[[${crypto.randomBytes(4).toString("hex")}]]`;

    return `${jVal()}
local ${v.t0} = tick()
local ${v.spy} = false

pcall(function()
  if type(hookfunction) == "function" then
    local _oh = game.HttpGet
    hookfunction(game.HttpGet, function(...)
      ${v.spy} = true
      return _oh(...)
    end)
  end
end)
if ${v.spy} then return end

pcall(function() if type(setclipboard) == "function" then setclipboard = function() end end end)
pcall(function() if type(writefile) == "function" then writefile = function() end end end)

${jVal()}
${cipherCode}
local ${v.keyVar} = "${keyEscaped}"
local ${v.subVar} = "${subEscaped}"

${jVal()}
local function ${v.decryptFn}(c, k, s)
  local cLen = #c
  local kLen = #k
  local out = {}
  local ${v._xor} = (bit32 and bit32.bxor) or function(a, b)
    local r, p = 0, 1
    while a > 0 or b > 0 do
      if a % 2 ~= b % 2 then r = r + p end
      a = (a - a % 2) / 2
      b = (b - b % 2) / 2
      p = p * 2
    end
    return r
  end

  for i = 1, cLen do
    local cb = string.byte(c, i)
    local kb = string.byte(k, ((i - 1) % kLen) + 1)
    out[i] = string.char(string.byte(s, ${v._xor}(cb, kb) + 1))
  end
  return table.concat(out)
end

${jVal()}
local ${v.decryptedVar} = ${v.decryptFn}(${v.cipherVar}, ${v.keyVar}, ${v.subVar})
${v.cipherVar} = nil
${v.keyVar} = nil
${v.subVar} = nil
${v.decryptFn} = nil

${jVal()}
if tick() - ${v.t0} > 15 then return end

local ${v.fnVar} = loadstring(${v.decryptedVar})
${v.decryptedVar} = nil

if type(${v.fnVar}) ~= "function" then return end

pcall(function()
  if setfenv then
    setfenv(${v.fnVar}, getfenv(0))
  end
end)

${v.fnVar}()
${v.fnVar} = nil
collectgarbage("collect")
${jVal()}`;
}

function isValidLoaderKey(key) {
    return typeof key === "string" && /^[\w.-]+\/[\w.-]+$/.test(key);
}

function resolveLoaderEntry(key) {
    if (!isValidLoaderKey(key)) return {
        status: "invalid"
    };
    const entry = LOADERS[key];
    if (!entry) return {
        status: "not_found"
    };
    if (entry.active === false) return {
        status: "disabled"
    };
    return {
        status: "ok",
        entry
    };
}

function getClientIp(req) {
    const fwd = req.headers["x-forwarded-for"] || "";
    const ip = fwd.split(",")[0].trim() ||
        req.headers["x-real-ip"] ||
        req.socket?.remoteAddress ||
        "unknown";
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
    const ua = req.headers["user-agent"] || "";
    const {
        penaltyHeaders,
        penalties
    } = CONFIG.executor;
    let score = 0;

    if (ua.length === 0) score += penalties.emptyUA;
    else if (ua.length < 5) score += penalties.shortUA;
    else if (ua.length > 400) score += penalties.longUA;

    for (const {
            header,
            score: s
        }
        of penaltyHeaders) {
        if (req.headers[header] !== undefined) score += s;
    }

    if (req.method === "GET") {
        const cl = parseInt(req.headers["content-length"] || "0", 10);
        if (cl > 0) score += penalties.getWithBody;
    }

    return score;
}

function checkRateLimit(ip) {
    const {
        windowMs,
        maxRequests
    } = CONFIG.rateLimit;
    const now = Date.now();
    const e = rateLimitStore.get(ip) || {
        count: 0,
        windowStart: now
    };

    if (now - e.windowStart > windowMs) {
        e.count = 1;
        e.windowStart = now;
        rateLimitStore.set(ip, e);
        return {
            limited: false
        };
    }

    e.count++;
    rateLimitStore.set(ip, e);

    if (e.count > maxRequests) {
        return {
            limited: true,
            retryAfter: Math.ceil((e.windowStart + windowMs - now) / 1000),
        };
    }

    return {
        limited: false
    };
}

function jitterDelay() {
    const {
        minMs,
        maxMs
    } = CONFIG.jitter;
    return new Promise(r =>
        setTimeout(r, minMs + Math.floor(Math.random() * (maxMs - minMs)))
    );
}

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
    res.setHeader("X-Request-Id", randomHex(8));
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

function buildBlockedPage() {
    const {
        page: p,
        fonts: f,
        tailwind: tw
    } = CONFIG;
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
      if(
        e.key==='F12'||
        (e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||
        (e.ctrlKey&&e.key==='U')
      ) e.preventDefault();
    });
  <\/script>
</body>
</html>`;
}

function sendBlocked(res) {
    applyBlockedCSP(res);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(buildBlockedPage());
}

const WHITELIST_LOCAL_PATH = process.env.WHITELIST_FILE ?
    path.resolve(process.cwd(), process.env.WHITELIST_FILE) :
    path.join(process.cwd(), "api/whitelist.json");

function normalizeLockType(value) {
    const v = String(value || "").trim().toLowerCase();
    if (v === "username" || v === "device") return v;
    return null;
}

function licenseError(res, status, code, message) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(status).json({
        success: false,
        code,
        message
    });
}

function readLocalWhitelist() {
    const candidates = [
        WHITELIST_LOCAL_PATH,
        path.join(process.cwd(), "Whitelisting-main/whitelist.json"),
        path.join(process.cwd(), "../Whitelisting-main/whitelist.json"),
        path.join(process.cwd(), "api/whitelist.json"),
    ];
    for (const file of candidates) {
        try {
            if (fs.existsSync(file)) {
                const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
                if (Array.isArray(parsed)) return parsed;
            }
        } catch {}
    }
    throw new Error("Whitelist file is unavailable.");
}

function githubConfigured() {
    return Boolean(
        process.env.GITHUB_TOKEN &&
        process.env.GITHUB_OWNER &&
        process.env.GITHUB_REPO &&
        process.env.GITHUB_WHITELIST_PATH
    );
}

async function githubWhitelist() {
    const url = `https://api.github.com/repos/${encodeURIComponent(process.env.GITHUB_OWNER)}/${encodeURIComponent(process.env.GITHUB_REPO)}/contents/${process.env.GITHUB_WHITELIST_PATH}`;
    const r = await fetch(url, {
        headers: {
            Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Flycer-License-API",
        },
        cache: "no-store",
    });
    if (!r.ok) throw new Error(`GitHub whitelist read failed: ${r.status}`);
    const data = await r.json();
    if (!data.content || !data.sha) throw new Error("GitHub whitelist response is invalid.");
    const text = Buffer.from(data.content.replace(/\s/g, ""), "base64").toString("utf8");
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new Error("Whitelist must be a JSON array.");
    return {
        data: parsed,
        sha: data.sha
    };
}

async function saveGithubWhitelist(list, sha) {
    const url = `https://api.github.com/repos/${encodeURIComponent(process.env.GITHUB_OWNER)}/${encodeURIComponent(process.env.GITHUB_REPO)}/contents/${process.env.GITHUB_WHITELIST_PATH}`;
    const content = Buffer.from(JSON.stringify(list, null, 2) + "\n", "utf8").toString("base64");
    const r = await fetch(url, {
        method: "PUT",
        headers: {
            Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Flycer-License-API",
        },
        body: JSON.stringify({
            message: "chore: bind Flycer license identifier",
            content,
            sha,
        }),
    });
    if (!r.ok) throw new Error(`GitHub whitelist write failed: ${r.status}`);
}

async function loadWhitelist() {
    if (githubConfigured()) return await githubWhitelist();
    return {
        data: readLocalWhitelist(),
        sha: null
    };
}

async function persistWhitelist(list, sha) {
    if (githubConfigured()) return await saveGithubWhitelist(list, sha);

    const target = WHITELIST_LOCAL_PATH;
    try {
        fs.mkdirSync(path.dirname(target), {
            recursive: true
        });
        fs.writeFileSync(target, JSON.stringify(list, null, 2) + "\n", "utf8");
    } catch (e) {
        throw new Error("Whitelist cannot be persisted.");
    }
}

function normalizeHwidList(entry) {
    const raw = entry["user hwid"];
    if (Array.isArray(raw)) {
        return raw.map(v => String(v).trim()).filter(Boolean);
    }
    if (typeof raw === "string" && raw.trim() !== "") {
        return [raw.trim()];
    }
    return [];
}

function getMaxDevices(entry) {
    const n = Number(entry.max_devices);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1;
}

function licenseIsExpired(entry, nowSeconds) {
    const type = String(entry["type key"] || "duration").toLowerCase();
    if (type === "free" || type === "lifetime") return false;
    const exp = Number(entry["expiredkey_timestamp"]);
    return !Number.isFinite(exp) || exp <= nowSeconds;
}

function safeLicenseInfo(entry, product, lockType) {
    const hwidList = normalizeHwidList(entry);
    return {
        product,
        key_type: String(entry["type key"] || "duration").toLowerCase(),
        lock_type: lockType || "none",
        expires_at: Number(entry["expiredkey_timestamp"]) || 0,
        devices_used: hwidList.length,
        devices_limit: getMaxDevices(entry),
    };
}

async function handleLicenseValidate(req, res) {
    if (isBrowserRequest(req)) return sendBlocked(res);

    if (req.method !== "POST") {
        res.setHeader("Allow", "POST");
        return licenseError(res, 405, "METHOD_NOT_ALLOWED", "Only POST is allowed.");
    }

    if (scoreSuspicion(req) >= CONFIG.suspicion.blockScore) {
        await jitterDelay();
        return licenseError(res, 403, "REQUEST_REJECTED", "Request rejected.");
    }

    const ip = getClientIp(req);
    const rl = checkRateLimit(ip);
    if (rl.limited) {
        res.setHeader("Retry-After", String(rl.retryAfter));
        return licenseError(res, 429, "RATE_LIMITED", "Too many requests.");
    }

    const body = await parseBody(req);
    if (!body || typeof body !== "object") {
        return licenseError(res, 400, "BAD_REQUEST", "Invalid JSON body.");
    }

    const product = String(body.product || "").trim();
    const key = String(body.key || "").trim();
    const lockType = normalizeLockType(body.lock_type);
    const identifier = String(body.identifier || "").trim();
    const client = String(body.client || "").trim();

    if (!product || !key || !lockType || !identifier) {
        return licenseError(res, 400, "MISSING_FIELDS", "Required fields are missing.");
    }

    await jitterDelay();

    let loaded;
    try {
        loaded = await loadWhitelist();
    } catch {
        return licenseError(res, 503, "WHITELIST_UNAVAILABLE", "License service error.");
    }

    const list = loaded.data;
    const now = Math.floor(Date.now() / 1000);

    const keyEntries = list.filter(entry =>
        entry && String(entry["user key"] || "").trim() === key
    );

    if (keyEntries.length === 0) {
        return licenseError(res, 404, "NOT_FOUND", "License key not found.");
    }

    let candidate = null;
    let rejectCode = "INVALID_LICENSE";
    let rejectMessage = "Invalid license.";

    for (const entry of keyEntries) {
        if (entry.active !== true) {
            rejectCode = "DISABLED";
            rejectMessage = "License disabled.";
            continue;
        }
        if (licenseIsExpired(entry, now)) {
            rejectCode = "EXPIRED";
            rejectMessage = "License expired.";
            continue;
        }
        candidate = entry;
        break;
    }

    if (!candidate) {
        return licenseError(res, 403, rejectCode, rejectMessage);
    }

    const entry = candidate;
    const keyType = String(entry["type key"] || "duration").toLowerCase();

    if (keyType === "free") {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.status(200).json({
            success: true,
            code: "VALID",
            message: "License validated successfully.",
            license: safeLicenseInfo(entry, product, "none"),
            client: client || undefined,
        });
    }

    const hwidList = normalizeHwidList(entry);
    const maxDevices = getMaxDevices(entry);

    if (hwidList.includes(identifier)) {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        return res.status(200).json({
            success: true,
            code: "VALID",
            message: "License validated successfully.",
            license: safeLicenseInfo(entry, product, lockType),
            client: client || undefined,
        });
    }

    if (hwidList.length >= maxDevices) {
        return licenseError(res, 403, "DEVICE_LIMIT_REACHED", `Key is already bound to ${maxDevices} device(s).`);
    }

    entry["user hwid"] = [...hwidList, identifier];

    try {
        await persistWhitelist(list, loaded.sha);
    } catch {
        return licenseError(res, 503, "BIND_PERSIST_FAILED", "Persistence error.");
    }

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(200).json({
        success: true,
        code: "BOUND",
        message: "License activated and bound.",
        license: safeLicenseInfo(entry, product, lockType),
        client: client || undefined,
    });
}

function getRoute(req) {
    const path = (req.url || "").split("?")[0].replace(/\/+$/, "");
    if (path === "/api/challenge") return "challenge";
    if (path === "/api/license/validate") return "license";
    if (path === "/api/gateway" || path === "/flycer") return "gateway";
    return "unknown";
}

function getQueryParam(req, name) {
    try {
        const u = new URL(req.url, "http://localhost");
        return u.searchParams.get(name);
    } catch {
        return null;
    }
}

async function parseBody(req) {
    if (req.body && typeof req.body === "object") return req.body;
    return new Promise(resolve => {
        let raw = "";
        req.on("data", c => {
            raw += c;
        });
        req.on("end", () => {
            try {
                resolve(JSON.parse(raw));
            } catch {
                resolve(null);
            }
        });
        req.on("error", () => resolve(null));
    });
}

async function handleChallenge(req, res) {
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

    const loaderKeyRaw = getQueryParam(req, "loader");
    const loaderKey = loaderKeyRaw ? decodeURIComponent(loaderKeyRaw) : null;

    if (req.method === "HEAD") return res.status(200).end();

    if (challengeStore.size >= CONFIG.challenge.maxStored) {
        const now = Date.now();
        for (const [id, d] of challengeStore) {
            if (now - d.timestamp > CONFIG.challenge.expiryMs) challengeStore.delete(id);
        }
    }

    await jitterDelay();

    const nonce = randomToken(24);
    const challenge_id = randomHex(16);
    const timestamp = Date.now();

    challengeStore.set(challenge_id, {
        nonce,
        timestamp,
        loaderKey
    });
    setTimeout(() => challengeStore.delete(challenge_id), CONFIG.challenge.expiryMs * 2);

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(200).json({
        challenge_id,
        nonce,
        timestamp
    });
}

async function handleGateway(req, res) {
    if (isBrowserRequest(req)) return sendBlocked(res);

    res.setHeader("Content-Type", "text/plain; charset=utf-8");

    if (!["POST", "HEAD"].includes(req.method)) {
        res.setHeader("Allow", "POST, HEAD");
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

    if (req.method === "HEAD") return res.status(200).end();

    const body = await parseBody(req);
    if (!body) return res.status(400).end("-- bad request");

    const {
        challenge_id,
        nonce,
        timestamp,
        signature
    } = body;

    if (!challenge_id || !nonce || !timestamp || !signature) {
        return res.status(400).end("-- missing fields");
    }

    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || ts <= 0) {
        return res.status(400).end("-- invalid timestamp");
    }

    const stored = challengeStore.get(challenge_id);
    if (!stored) {
        await jitterDelay();
        return res.status(403).end("-- challenge expired");
    }

    if (stored.nonce !== nonce) {
        challengeStore.delete(challenge_id);
        await jitterDelay();
        return res.status(403).end("-- invalid nonce");
    }

    const age = Date.now() - ts;
    if (age < 0 || age > CONFIG.challenge.expiryMs) {
        challengeStore.delete(challenge_id);
        await jitterDelay();
        return res.status(403).end("-- challenge expired");
    }

    if (!verifySignature(nonce, ts, challenge_id, signature)) {
        challengeStore.delete(challenge_id);
        await jitterDelay();
        return res.status(403).end("-- invalid signature");
    }

    const loaderKey = stored.loaderKey;
    challengeStore.delete(challenge_id);

    const resolved = resolveLoaderEntry(loaderKey);
    if (resolved.status !== "ok") {
        await jitterDelay();
        return res.status(404).end("-- loader not found");
    }

    await jitterDelay();

    // SERVER-SIDE FETCH & PROXY DELIVERY
    let rawSource;
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        const fetchRes = await fetch(resolved.entry.url, {
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!fetchRes.ok) throw new Error("Fetch failed");
        rawSource = await fetchRes.text();
    } catch {
        return res.status(502).end("-- script compilation error");
    }

    return res.status(200).end(buildLoader(rawSource));
}

export default async function handler(req, res) {
    applyBaseHeaders(res);

    const route = getRoute(req);
    if (route === "challenge") return handleChallenge(req, res);
    if (route === "license") return handleLicenseValidate(req, res);
    if (route === "gateway") return handleGateway(req, res);

    if (isBrowserRequest(req)) return sendBlocked(res);
    return res.status(404).end("-- not found");
}
