// ══════════════════════════════════════════════════════════════════════════
//  CENTRAL CONFIG — Edit only this file for customization
// ══════════════════════════════════════════════════════════════════════════

export const CONFIG = {

    // ── Secrets (set via Vercel Environment Variables) ──
    secrets: {
        hmacKey: process.env.HMAC_SECRET || "CHANGE_ME_hmac_secret_32chars!!",
        tokenSalt: process.env.TOKEN_SALT || "CHANGE_ME_salt_value_unique!!!!!",
    },

    // ── Loader URL ──
    loader: {
        url: process.env.LOADER_URL ||
            "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test",
    },

    // ── Challenge / Token Settings ──
    challenge: {
        expirySeconds: 15, // Redis TTL — challenge valid for 15s
        nonceLength: 24, // bytes for nonce
        idLength: 16, // bytes for challenge_id
    },

    // ── Rate Limit (per endpoint, per IP) ──
    rateLimit: {
        challenge: {
            max: 6, // requests allowed
            windowSec: 60, // per 60 seconds
        },
        gateway: {
            max: 4,
            windowSec: 60,
        },
        ban: {
            threshold: 5, // violations before temp ban
            durationSec: 600, // 10 minute ban
        },
    },

    // ── Browser Detection ──
    browser: {
        // UA substrings that indicate a browser or tool
        keywords: [
            "mozilla", "chrome", "safari", "firefox", "edge",
            "opera", "brave", "vivaldi", "webkit", "gecko",
            "trident", "msie", "headlesschrome", "phantomjs",
            "selenium", "puppeteer", "playwright",
            "curl", "wget", "httpie", "postman", "insomnia",
            "axios", "python-requests", "go-http", "java/",
            "libwww", "perl", "ruby", "bot", "spider", "crawl",
            "googlebot", "bingbot", "yandex", "baidu",
            "facebookexternalhit", "twitterbot", "discord",
            "telegram", "whatsapp", "slack",
        ],
        // UA substrings that are ALLOWED even if above matches
        allowlist: ["roblox"],
        // Suspicious headers that browsers send but executors don't
        browserOnlyHeaders: [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "upgrade-insecure-requests",
        ],
    },

    // ── Executor Suspicion Thresholds ──
    suspicion: {
        blockScore: 10, // score >= this → send decoy
        penaltyHeaders: [ // each present header adds penalty
            {
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
            shortUA: 3, // UA under 5 chars
            longUA: 2, // UA over 400 chars
            getWithBody: 5,
        },
    },

    // ── Response Jitter (ms) ──
    jitter: {
        minMs: 40,
        maxMs: 130,
    },

    // ── Blocked Page Content ──
    page: {
        title: "Gateway Loader",
        badge: "403 Forbidden",
        heading: {
            prefix: "ACCESS",
            highlight: "DENIED",
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
        footer: "Flycer Loader \u00A0·\u00A0 Restricted Access",
    },

    // ── Fonts / CDN ──
    fonts: {
        body: "'Inter', sans-serif",
        mono: "'JetBrains Mono', monospace",
        url: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
    },
    tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",
};
