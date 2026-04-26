// ══════════════════════════════════════════════════════════════════════════
//  SECURITY HELPERS — Browser detection, executor analysis, headers
// ══════════════════════════════════════════════════════════════════════════

import { CONFIG } from "./config.js";
import { randomHex } from "./crypto.js";

// ── IP Extraction ─────────────────────────────────────────────────────────

export function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"] || "";
  const ip = forwarded.split(",")[0].trim()
    || req.headers["x-real-ip"]
    || req.socket?.remoteAddress
    || "unknown";

  // Normalize IPv6-mapped IPv4 addresses
  return ip.replace(/^::ffff:/, "").trim();
}

// ── Browser Detection ─────────────────────────────────────────────────────

/**
 * Returns true if the request appears to come from a browser or tool.
 * Checks: User-Agent, browser-only headers, Accept header.
 */
export function isBrowserRequest(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // Always allow known executor signatures
  const isAllowed = CONFIG.browser.allowlist.some((k) => ua.includes(k));
  if (isAllowed) return false;

  // Block by User-Agent keywords
  const hasBrowserUA = CONFIG.browser.keywords.some((k) => ua.includes(k));
  if (hasBrowserUA) return true;

  // Block if browser-specific security headers are present
  const hasBrowserHeaders = CONFIG.browser.browserOnlyHeaders.some(
    (h) => req.headers[h] !== undefined
  );
  if (hasBrowserHeaders) return true;

  // Block if Accept header looks like a browser's
  const accept = (req.headers["accept"] || "").toLowerCase();
  if (accept.includes("text/html") && accept.includes("application/xhtml+xml")) {
    return true;
  }

  return false;
}

// ── Executor Suspicion Scorer ─────────────────────────────────────────────

/**
 * Scores how suspicious a request looks.
 * Higher = more suspicious. 0 = clean.
 *
 * Returns { score: number, reasons: string[] }
 */
export function scoreExecutorSuspicion(req) {
  const ua      = req.headers["user-agent"] || "";
  const { penalties, penaltyHeaders } = CONFIG.suspicion;

  let score   = 0;
  const reasons = [];

  // ── UA length checks ──
  if (ua.length === 0) {
    score += penalties.emptyUA;
    reasons.push("ua:empty");
  } else if (ua.length < 5) {
    score += penalties.shortUA;
    reasons.push("ua:too_short");
  } else if (ua.length > 400) {
    score += penalties.longUA;
    reasons.push("ua:too_long");
  }

  // ── Penalty headers ──
  for (const { header, score: headerScore } of penaltyHeaders) {
    if (req.headers[header] !== undefined) {
      score += headerScore;
      reasons.push(`header:${header}`);
    }
  }

  // ── GET with body ──
  if (req.method === "GET") {
    const cl = parseInt(req.headers["content-length"] || "0", 10);
    if (cl > 0) {
      score += penalties.getWithBody;
      reasons.push("get:has_body");
    }
  }

  return { score, reasons };
}

// ── Security Headers ──────────────────────────────────────────────────────

/**
 * Apply hardened security headers to every response.
 */
export function applySecurityHeaders(res) {
  // Sniff & frame protection
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "0");           // Modern: disable legacy XSS filter

  // Crawler / indexing
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");

  // Cache — never cache gateway responses
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma",  "no-cache");
  res.setHeader("Expires", "0");

  // Referrer & permissions
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "interest-cohort=(), geolocation=(), camera=()");

  // HSTS
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );

  // CSP — locked down; blocked page overrides this for fonts/tailwind
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'none'",
      "style-src 'none'",
      "img-src 'none'",
      "connect-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'none'",
    ].join("; ")
  );

  // Hide server identity
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");

  // Unique request trace (for logging)
  res.setHeader("X-Request-Id", randomHex(8));
}

/**
 * Override CSP for the browser blocked page
 * (needs fonts & tailwind CDN)
 */
export function applyBlockedPageHeaders(res) {
  applySecurityHeaders(res);
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'unsafe-inline' https://cdn.jsdelivr.net",
      "style-src 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "img-src 'none'",
      "connect-src 'none'",
      "frame-ancestors 'none'",
    ].join("; ")
  );
}

// ── Method Guard ──────────────────────────────────────────────────────────

export function isAllowedMethod(method, allowed = ["GET", "HEAD"]) {
  return allowed.includes(method?.toUpperCase());
}

// ── Jitter ────────────────────────────────────────────────────────────────

export function applyJitter() {
  const { minMs, maxMs } = CONFIG.jitter;
  const delay = minMs + Math.floor(Math.random() * (maxMs - minMs));
  return new Promise((resolve) => setTimeout(resolve, delay));
}
