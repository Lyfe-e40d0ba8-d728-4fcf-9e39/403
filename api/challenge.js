// ══════════════════════════════════════════════════════════════════════════
//  /api/challenge  —  Step 1: Request a one-time challenge
//
//  Executor calls:  GET /api/challenge
//  Server returns:  { challenge_id, nonce, timestamp }
//  Valid for:       CONFIG.challenge.expirySeconds seconds (Redis TTL)
// ══════════════════════════════════════════════════════════════════════════

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
    randomHex,
    randomToken
} from "./_lib/crypto.js";
import {
    checkRedisRateLimit,
    checkBan
} from "./_lib/redis.js";
import {
    buildBlockedPage
} from "./_lib/html.js";

export default async function handler(req, res) {
    const ip = getClientIp(req);

    // ── Layer 0: Security headers ─────────────────────────────────────────
    applySecurityHeaders(res);

    // ── Layer 1: Method guard ─────────────────────────────────────────────
    if (!isAllowedMethod(req.method, ["GET", "HEAD"])) {
        res.setHeader("Allow", "GET, HEAD");
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
    const {
        score
    } = scoreExecutorSuspicion(req);
    if (score >= CONFIG.suspicion.blockScore) {
        await applyJitter();
        return res.status(200)
            .setHeader("Content-Type", "text/plain; charset=utf-8")
            .end("-- error");
    }

    // ── Layer 4: Ban check ────────────────────────────────────────────────
    const banResult = await checkBan(
        ip,
        CONFIG.rateLimit.ban.threshold,
        CONFIG.rateLimit.ban.durationSec
    );
    if (banResult.banned) {
        res.setHeader("Retry-After", String(banResult.retryAfter));
        return res.status(429)
            .setHeader("Content-Type", "text/plain; charset=utf-8")
            .end("-- rate limited");
    }

    // ── Layer 5: Rate limit ───────────────────────────────────────────────
    const {
        challenge
    } = CONFIG.rateLimit;
    const rlResult = await checkRedisRateLimit(
        `rl:challenge:${ip}`,
        challenge.max,
        challenge.windowSec
    );
    if (rlResult.limited) {
        res.setHeader("Retry-After", String(rlResult.retryAfter));
        return res.status(429)
            .setHeader("Content-Type", "text/plain; charset=utf-8")
            .end("-- rate limited");
    }

    // ── HEAD: no body needed ──────────────────────────────────────────────
    if (req.method === "HEAD") return res.status(200).end();

    // ── Layer 6: Jitter ───────────────────────────────────────────────────
    await applyJitter();

    // ── Generate challenge ────────────────────────────────────────────────
    const {
        redisSet
    } = await import("./_lib/redis.js");
    const {
        expirySeconds
    } = CONFIG.challenge;

    const nonce = randomToken(CONFIG.challenge.nonceLength);
    const challenge_id = randomHex(CONFIG.challenge.idLength);
    const timestamp = Date.now();

    // Store in Redis: key = challenge:{id}, value = { nonce, timestamp }
    await redisSet(
        `challenge:${challenge_id}`, {
            nonce,
            timestamp
        },
        expirySeconds
    );

    // ── Respond ───────────────────────────────────────────────────────────
    return res.status(200)
        .setHeader("Content-Type", "application/json; charset=utf-8")
        .json({
            challenge_id,
            nonce,
            timestamp
        });
}
