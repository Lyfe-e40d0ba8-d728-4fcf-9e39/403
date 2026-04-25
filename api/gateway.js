// ══════════════════════════════════════════════════════════════════════════
//  /api/gateway  —  Step 2: Submit challenge response → receive Lua loader
//
//  Executor calls:  POST /api/gateway
//  Body (JSON):     { challenge_id, nonce, timestamp, signature }
//  Returns:         Lua script (text/plain)
//
//  Signature:       HMAC-SHA256(secret, nonce + ":" + timestamp + ":" + challenge_id)
// ══════════════════════════════════════════════════════════════════════════

import { CONFIG }                   from "./_lib/config.js";
import { getClientIp,
         isBrowserRequest,
         scoreExecutorSuspicion,
         applySecurityHeaders,
         applyBlockedPageHeaders,
         isAllowedMethod,
         applyJitter }              from "./_lib/security.js";
import { verifyChallengeSignature } from "./_lib/crypto.js";
import { checkRedisRateLimit,
         checkBan,
         redisGet,
         redisDel }                 from "./_lib/redis.js";
import { buildBlockedPage }         from "./_lib/html.js";

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
  return new Promise((resolve) => {
    // Vercel typically parses JSON automatically
    // This handles edge cases where it doesn't
    if (req.body && typeof req.body === "object") {
      return resolve(req.body);
    }

    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
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

// ── Main Handler ──────────────────────────────────────────────────────────

export default async function handler(req, res) {
  const ip = getClientIp(req);

  // ── Layer 0: Security headers ─────────────────────────────────────────
  applySecurityHeaders(res);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");

  // ── Layer 1: Method guard (POST only for submission) ──────────────────
  if (!isAllowedMethod(req.method, ["POST", "HEAD"])) {
    res.setHeader("Allow", "POST, HEAD");
    return res.status(405).end("-- method not allowed");
  }

  // ── Layer 2: Browser block ────────────────────────────────────────────
  if (isBrowserRequest(req)) {
    applyBlockedPageHeaders(res);
    return res.status(200)
              .setHeader("Content-Type", "text/html; charset=utf-8")
              .send(buildBlockedPage());
  }

  // ── Layer 3: Suspicion check ──────────────────────────────────────────
  const { score } = scoreExecutorSuspicion(req);
  if (score >= CONFIG.suspicion.blockScore) {
    await applyJitter();
    return res.status(200).end("-- error");
  }

  // ── Layer 4: Ban check ────────────────────────────────────────────────
  const banResult = await checkBan(
    ip,
    CONFIG.rateLimit.ban.threshold,
    CONFIG.rateLimit.ban.durationSec
  );
  if (banResult.banned) {
    res.setHeader("Retry-After", String(banResult.retryAfter));
    return res.status(429).end("-- rate limited");
  }

  // ── Layer 5: Rate limit ───────────────────────────────────────────────
  const { gateway } = CONFIG.rateLimit;
  const rlResult = await checkRedisRateLimit(
    `rl:gateway:${ip}`,
    gateway.max,
    gateway.windowSec
  );
  if (rlResult.limited) {
    res.setHeader("Retry-After", String(rlResult.retryAfter));
    return res.status(429).end("-- rate limited");
  }

  // ── HEAD: no body needed ──────────────────────────────────────────────
  if (req.method === "HEAD") return res.status(200).end();

  // ── Layer 6: Parse & validate body ───────────────────────────────────
  const body = await parseBody(req);

  if (!body) {
    return res.status(400).end("-- bad request");
  }

  const { challenge_id, nonce, timestamp, signature } = body;

  // All fields required
  if (!challenge_id || !nonce || !timestamp || !signature) {
    return res.status(400).end("-- missing fields");
  }

  // Timestamp must be a number
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || ts <= 0) {
    return res.status(400).end("-- invalid timestamp");
  }

  // ── Layer 7: Challenge lookup (anti-replay via Redis) ─────────────────
  const stored = await redisGet(`challenge:${challenge_id}`);

  if (!stored) {
    // Challenge expired or never existed
    await applyJitter();
    return res.status(403).end("-- challenge expired");
  }

  // ── Layer 8: Nonce match ──────────────────────────────────────────────
  if (stored.nonce !== nonce) {
    await redisDel(`challenge:${challenge_id}`);
    await applyJitter();
    return res.status(403).end("-- invalid nonce");
  }

  // ── Layer 9: Timestamp freshness ──────────────────────────────────────
  const ageMs = Date.now() - ts;
  if (ageMs < 0 || ageMs > CONFIG.challenge.expirySeconds * 1000) {
    await redisDel(`challenge:${challenge_id}`);
    await applyJitter();
    return res.status(403).end("-- challenge expired");
  }

  // ── Layer 10: HMAC Signature ──────────────────────────────────────────
  const sigValid = verifyChallengeSignature(nonce, ts, challenge_id, signature);
  if (!sigValid) {
    await redisDel(`challenge:${challenge_id}`);
    await applyJitter();
    return res.status(403).end("-- invalid signature");
  }

  // ── Layer 11: Consume challenge (TRUE one-time use) ───────────────────
  await redisDel(`challenge:${challenge_id}`);

  // ── Layer 12: Jitter before delivery ─────────────────────────────────
  await applyJitter();

  // ── Deliver loader ────────────────────────────────────────────────────
  return res.status(200).end(buildLoaderScript());
}
