// ══════════════════════════════════════════════════════════════════════════
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════════════════════

import crypto from "crypto";
import {
    CONFIG
} from "./config.js";

/**
 * Generate a cryptographically secure random hex string
 */
export function randomHex(bytes = 16) {
    return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Generate a URL-safe base64 token
 */
export function randomToken(bytes = 24) {
    return crypto.randomBytes(bytes).toString("base64url");
}

/**
 * HMAC-SHA256 — returns hex digest
 */
export function hmacSign(data) {
    return crypto
        .createHmac("sha256", CONFIG.secrets.hmacKey)
        .update(String(data))
        .digest("hex");
}

/**
 * Constant-time string comparison (prevent timing attacks)
 */
export function safeCompare(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    if (a.length !== b.length) {
        // Still run comparison to avoid timing leak
        crypto.timingSafeEqual(
            Buffer.from(a),
            Buffer.from(a)
        );
        return false;
    }
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

/**
 * Build the HMAC signature for a challenge response
 * Data = nonce + ":" + timestamp + ":" + challenge_id
 */
export function buildChallengeSignature(nonce, timestamp, challengeId) {
    const data = `${nonce}:${timestamp}:${challengeId}`;
    return hmacSign(data);
}

/**
 * Verify a challenge response signature
 */
export function verifyChallengeSignature(nonce, timestamp, challengeId, sig) {
    const expected = buildChallengeSignature(nonce, timestamp, challengeId);
    return safeCompare(expected, sig);
}
