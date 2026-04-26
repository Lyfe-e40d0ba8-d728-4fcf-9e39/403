// ══════════════════════════════════════════════════════════════════════════
//  /api/gateway  —  Step 2: Submit challenge response → receive Lua loader
//
//  Executor calls:  POST /api/gateway
//  Body (JSON):     { challenge_id, nonce, timestamp, signature }
//  Returns:         Lua script (text/plain)
//
//  Signature:       HMAC-SHA256(secret, nonce + ":" + timestamp + ":" + challenge_id)
// ══════════════════════════════════════════════════════════════════════════
import { validateEnv } from "./_lib/validate-env.js";
validateEnv();

import {
    CONFIG
} from "./_lib/config.js";
import {
    getClientIp,
    isBrowserRequest,
    scoreExecutorSuspicion,
    applySecurityHeaders,
    applyBlockedPageHeaders,
    isAllowedMethod,
    applyJitter
} from "./_lib/security.js";
import {
    verifyChallengeSignature
} from "./_lib/crypto.js";
import {
    checkRedisRateLimit,
    checkBan,
    redisGet,
    redisDel
} from "./_lib/redis.js";
import {
    buildBlockedPage
} from "./_lib/html.js";

// ── Lua Loader Builder ────────────────────────────────────────────────────

function buildLoaderScript() {
    const url = CONFIG.loader.url;

    // Clean, executor-compatible Lua
    // - No bit32 / bitwise ops (works on ALL executors)
    // - game:HttpGet colon syntax (PC & Mobile)
    // - pcall wrapper for safe fetch
    // - Nils sensitive vars after use
    // - collectgarbage cleans up memory
    return `-- Flycer Loader
local _url = "${url}"
local _ok, _src = pcall(function()
  return game:HttpGet(_url)
end)
if not _ok or type(_src) ~= "string" or #_src == 0 then
  return -- silent fail, no crash
end
local _fn = loadstring(_src)
if type(_fn) ~= "function" then
  return -- invalid payload
end
_url = nil
_ok  = nil
_src = nil
_fn()
_fn  = nil
collectgarbage("collect")`;
}

// ── Body Parser Helper ────────────────────────────────────────────────────

async function parseBody(req) {
    // 1. Vercel built-in body parsing (FAST PATH)
    if (req.body && typeof req.body === "object") {
        return req.body;
    }

    try {
        // 2. Stream fallback (safe for raw requests)
        const chunks = [];

        for await (const chunk of req) {
            chunks.push(chunk);
        }

        const raw = Buffer.concat(chunks).toString("utf8");

        if (!raw || raw.length === 0) return null;

        return JSON.parse(raw);
    } catch (err) {
        return null;
    }
}

// ── Main Handler ──────────────────────────────────────────────────────────

export default async function handler(req, res) {
    const ip = getClientIp(req);

    applySecurityHeaders(res);

    if (!req.headers["user-agent"] && req.method === "POST") {
        return res.status(403).end("-- blocked");
    }

    // ── Layer 1: Method guard ─────────────────────────────
    if (req.method === "GET") {
        applyBlockedPageHeaders(res);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(200).end(buildBlockedPage());
    }

    if (isBrowserRequest(req)) {
        applyBlockedPageHeaders(res);
        return res.status(200).end(buildBlockedPage());
    }

    if (!isAllowedMethod(req.method, ["POST", "HEAD"])) {
        res.setHeader("Allow", "POST, HEAD");
        return res.status(405).end("-- method not allowed");
    }

    // ── Layer 4: Suspicion check ───────────────────────────
    const {
        score
    } = scoreExecutorSuspicion(req);
    const blockScore = CONFIG?.suspicion?.blockScore ?? 10;

    if (typeof score === "number" && score >= blockScore) {
        await applyJitter();

        // stealth response (no clear signal)
        return res.status(200).end("-- ok");
    }

    // ── Layer 5: Ban check ────────────────────────────────
    const banResult = await checkBan(ip, CONFIG.rateLimit.ban.threshold, CONFIG.rateLimit.ban.durationSec);
    if (banResult.banned) {
        res.setHeader("Retry-After", String(banResult.retryAfter));
        return res.status(429).end("-- rate limited");
    }

    // ── Layer 6: Rate limit ───────────────────────────────
    const {
        gateway
    } = CONFIG.rateLimit;
    const rlResult = await checkRedisRateLimit(
        `rl:gateway:${ip}`,
        gateway.max,
        gateway.windowSec
    );

    if (rlResult.limited) {
        res.setHeader("Retry-After", String(rlResult.retryAfter));
        return res.status(429).end("-- rate limited");
    }

    if (req.method === "HEAD") return res.status(200).end();

    // ── SAFE BODY PARSE (VERCEL FRIENDLY) ────────────────
    const body = await parseBody(req);
    if (!body) return res.status(400).end("-- bad request");
}

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
if (!Number.isFinite(ts)) {
    return res.status(400).end("-- invalid timestamp");
}

// ── Redis check ───────────────────────────────
const stored = await redisGet(`challenge:${challenge_id}`);
if (!stored) {
    await applyJitter();
    return res.status(403).end("-- expired");
}

if (stored.nonce !== nonce) {
    await redisDel(`challenge:${challenge_id}`);
    return res.status(403).end("-- invalid nonce");
}

const now = Date.now();
const skew = Math.abs(now - ts);

if (skew > CONFIG.challenge.expirySeconds * 1000) {
    return res.status(403).end("-- expired");
}

const sigValid = verifyChallengeSignature(nonce, ts, challenge_id, signature);
if (!sigValid) {
    await redisDel(`challenge:${challenge_id}`);
    return res.status(403).end("-- invalid signature");
}

await redisDel(`challenge:${challenge_id}`);

await applyJitter();

// ── RESPONSE ───────────────────────────────
res.setHeader("Content-Type", "text/plain; charset=utf-8");
return res.status(200).end(buildLoaderScript());
}
