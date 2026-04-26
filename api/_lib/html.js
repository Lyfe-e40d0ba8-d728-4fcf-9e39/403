// ══════════════════════════════════════════════════════════════════════════
//  HTML — Blocked page templates
// ══════════════════════════════════════════════════════════════════════════

import { CONFIG } from "./config.js";

// ─────────────────────────────────────────────────────────────
// 1. Normal Blocked Page
// ─────────────────────────────────────────────────────────────

export function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;
  const subtitleHtml = page.subtitle.join("<br/>");
  const warningLinesHtml = page.warning.lines.join("<br/>");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <meta name="robots" content="noindex,nofollow,noarchive"/>
  <title>${page.title}</title>
  <script src="${tailwind}"></script>
  <link href="${fonts.url}" rel="stylesheet"/>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{
      background:#0d0d0f;font-family:${fonts.body};
      overflow:hidden;height:100vh;width:100vw;
      display:flex;align-items:center;justify-content:center;
      -webkit-user-select:none;user-select:none;
    }
    .card{
      background:#141416;
      border:1px solid rgba(255,255,255,.07);
      border-radius:16px;
      padding:44px;
      width:420px;
      text-align:center;
    }
    .badge{
      display:inline-flex;
      padding:6px 12px;
      background:rgba(239,68,68,.1);
      border:1px solid rgba(239,68,68,.2);
      border-radius:999px;
      color:#f87171;
      font-size:12px;
      margin-bottom:20px;
    }
    .title{color:#fff;font-size:22px;margin-bottom:10px}
    .sub{color:#aaa;font-size:13px;margin-bottom:20px}
    .warn{color:#fca5a5;font-size:12px;line-height:1.6}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">${page.badge}</div>
    <div class="title">${page.heading.prefix} <span>${page.heading.highlight}</span></div>
    <div class="sub">${subtitleHtml}</div>
    <div class="warn"><strong>${page.warning.bold}</strong><br/>${warningLinesHtml}</div>
  </div>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────
// 2. Enterprise Block Page
// ─────────────────────────────────────────────────────────────

export function buildEnterpriseBlockPage() {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Check</title>
<style>
body{
  margin:0;
  background:#0b0f17;
  color:#e5e7eb;
  font-family:system-ui;
  display:flex;
  height:100vh;
  align-items:center;
  justify-content:center;
}
.box{
  max-width:520px;
  padding:30px;
  border:1px solid #1f2937;
  border-radius:14px;
  background:#0f172a;
  text-align:center;
}
h1{color:#60a5fa;font-size:22px;margin-bottom:10px}
p{color:#94a3b8;font-size:14px;line-height:1.6}
.badge{
  display:inline-block;
  padding:4px 10px;
  background:#1e293b;
  border:1px solid #334155;
  border-radius:999px;
  font-size:12px;
  margin-bottom:15px;
}
</style>
</head>
<body>
<div class="box">
  <div class="badge">SECURITY VERIFICATION</div>
  <h1>Access Restricted</h1>
  <p>
    This endpoint is protected by an automated security gateway.<br/>
    Your request has been blocked or requires validation.
  </p>
</div>
</body>
</html>`;
}
