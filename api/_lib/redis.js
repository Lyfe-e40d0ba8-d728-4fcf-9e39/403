// ══════════════════════════════════════════════════════════════════════════
//  REDIS CLIENT — Upstash (HTTP-based, works on Vercel Edge/Serverless)
// ══════════════════════════════════════════════════════════════════════════

// ── Upstash REST Client (no native driver needed) ────────────────────────

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

/**
 * Raw Upstash REST call
 * @param  {...any} args — Redis command array e.g. ["SET", "key", "val"]
 * @returns {Promise<any>}
 */
async function redisCommand(...args) {
    if (!REDIS_URL || !REDIS_TOKEN) {
        // Fallback: no-op when Redis is not configured
        // Loader still works, just without persistent rate-limit/anti-replay
        console.warn("[redis] UPSTASH env vars not set — skipping Redis call");
        return null;
    }

    const res = await fetch(`${REDIS_URL}`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${REDIS_TOKEN}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(args),
    });

    if (!res.ok) {
        console.error(`[redis] HTTP ${res.status} — ${await res.text()}`);
        return null;
    }

    const json = await res.json();
    return json.result ?? null;
}

// ── High-level helpers ───────────────────────────────────────────────────

/**
 * SET key value EX seconds
 */
export async function redisSet(key, value, exSeconds) {
    return redisCommand("SET", key, JSON.stringify(value), "EX", exSeconds);
}

/**
 * GET key → parsed JSON (or null)
 */
export async function redisGet(key) {
    const raw = await redisCommand("GET", key);
    if (raw === null || raw === undefined) return null;
    try {
        return JSON.parse(raw);
    } catch {
        return raw;
    }
}

/**
 * DEL key
 */
export async function redisDel(key) {
    return redisCommand("DEL", key);
}

/**
 * INCR key → new count
 */
export async function redisIncr(key) {
    return redisCommand("INCR", key);
}

/**
 * EXPIRE key seconds
 */
export async function redisExpire(key, seconds) {
    return redisCommand("EXPIRE", key, seconds);
}

/**
 * Check + increment rate limit for a given key.
 *
 * Returns: { limited: bool, count: number, retryAfter: number }
 */
export async function checkRedisRateLimit(key, max, windowSec) {
    try {
        const count = await redisIncr(key);

        // On first request — set expiry
        if (count === 1) {
            await redisExpire(key, windowSec);
        }

        if (count > max) {
            // TTL tells us when the window resets
            const ttl = await redisCommand("TTL", key);
            return {
                limited: true,
                count,
                retryAfter: ttl > 0 ? ttl : windowSec,
            };
        }

        return {
            limited: false,
            count,
            retryAfter: 0
        };
    } catch (err) {
        console.error("[redis] rate limit error:", err);
        // Fail open — don't block legitimate requests if Redis is down
        return {
            limited: false,
            count: 0,
            retryAfter: 0
        };
    }
}

/**
 * Track ban violations.
 * Returns: { banned: bool, retryAfter: number }
 */
export async function checkBan(ip, threshold, durationSec) {
    const banKey = `ban:${ip}`;
    const violationKey = `violations:${ip}`;

    // Check active ban first
    const banTtl = await redisCommand("TTL", banKey);
    if (banTtl > 0) {
        return {
            banned: true,
            retryAfter: banTtl
        };
    }

    // Increment violations
    const violations = await redisIncr(violationKey);
    if (violations === 1) {
        // Violations expire after 10 minutes of inactivity
        await redisExpire(violationKey, 600);
    }

    if (violations >= threshold) {
        // Set ban
        await redisSet(banKey, "1", durationSec);
        await redisDel(violationKey);
        return {
            banned: true,
            retryAfter: durationSec
        };
    }

    return {
        banned: false,
        retryAfter: 0
    };
}
