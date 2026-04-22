// ══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════════════════════

const CONFIG = {

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
    footer: "Flycer Loader · Restricted Access",
  },

  // ✅ FIXED (langsung URL, tidak ribet lagi)
  loader: {
    url: "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test",
  },

  browser: {
    keywords: ["mozilla", "chrome", "safari", "firefox", "edge"],
    exclude: ["roblox"],
  },

  fonts: {
    body: "'Inter', sans-serif",
    mono: "'JetBrains Mono', monospace",
    url: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap",
  },

  tailwind: "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4",
};

// ══════════════════════════════════════════════════════════════════════════════
// ENGINE
// ══════════════════════════════════════════════════════════════════════════════

function isBrowserRequest(userAgent = "") {
  const ua = userAgent.toLowerCase();
  const isBrowser = CONFIG.browser.keywords.some(k => ua.includes(k));
  const isExcluded = CONFIG.browser.exclude.some(k => ua.includes(k));
  return isBrowser && !isExcluded;
}

// ── Loader ─────────────────────────────────────────

// ✅ FIX: langsung return URL
function buildLoaderUrl() {
  return CONFIG.loader.url;
}

function buildLoaderScript() {
  return `loadstring(game:HttpGet("${buildLoaderUrl()}"))()`;
}

// ── HTML ───────────────────────────────────────────

function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${page.title}</title>
<script src="${tailwind}"><\/script>
<link href="${fonts.url}" rel="stylesheet">
<style>
body {
  margin:0;
  background:#0d0d0f;
  font-family:${fonts.body};
  display:flex;
  align-items:center;
  justify-content:center;
  height:100vh;
  color:white;
}
.card {
  background:#141416;
  padding:40px;
  border-radius:14px;
  text-align:center;
  border:1px solid rgba(255,255,255,0.08);
}
.title span { color:#ef4444; }
.subtitle { opacity:.6; margin:10px 0 20px; }
</style>
</head>
<body>
<div class="card">
  <h1 class="title">${page.heading.prefix} <span>${page.heading.highlight}</span></h1>
  <div class="subtitle">${page.subtitle.join("<br>")}</div>
  <div><b>${page.warning.bold}</b><br>${page.warning.lines.join("<br>")}</div>
  <div style="margin-top:20px;font-size:12px;opacity:.3">${page.footer}</div>
</div>
</body>
</html>`;
}

// ── Handler ────────────────────────────────────────

export default async function handler(req, res) {
  const userAgent = req.headers["user-agent"] || "";

  // 🔒 Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store");

  // ⛔ Block browser
  if (isBrowserRequest(userAgent)) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(buildBlockedPage());
  }

  // ⚡ Anti spam delay
  await new Promise(r => setTimeout(r, 120));

  // 🚀 Loader
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildLoaderScript());
}
