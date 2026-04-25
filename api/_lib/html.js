// ══════════════════════════════════════════════════════════════════════════
//  HTML — Blocked page template
// ══════════════════════════════════════════════════════════════════════════

import { CONFIG } from "./config.js";

export function buildBlockedPage() {
  const { page, fonts, tailwind } = CONFIG;
  const subtitleHtml     = page.subtitle.join("<br/>");
  const warningLinesHtml = page.warning.lines.join("<br/>");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <meta name="robots" content="noindex,nofollow,noarchive"/>
  <title>${page.title}</title>
  <script src="${tailwind}"><\/script>
  <link href="${fonts.url}" rel="stylesheet"/>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{
      background:#0d0d0f;font-family:${fonts.body};
      overflow:hidden;height:100vh;width:100vw;
      display:flex;align-items:center;justify-content:center;
      -webkit-user-select:none;user-select:none;
    }
    body::before{
      content:'';position:fixed;inset:0;
      background:radial-gradient(ellipse at center,transparent 30%,rgba(0,0,0,.65) 100%);
      pointer-events:none;z-index:0;
    }
    body::after{
      content:'';position:fixed;inset:0;
      background-image:radial-gradient(circle,rgba(255,255,255,.04) 1px,transparent 1px);
      background-size:28px 28px;pointer-events:none;z-index:0;
    }
    .card{
      position:relative;z-index:10;background:#141416;
      border:1px solid rgba(255,255,255,.07);border-radius:16px;
      box-shadow:0 0 0 1px rgba(255,255,255,.03),0 32px 80px rgba(0,0,0,.7),0 8px 24px rgba(0,0,0,.5);
      padding:44px 48px 40px;width:420px;max-width:92vw;
      animation:cardIn .6s cubic-bezier(.16,1,.3,1) forwards;text-align:center;
    }
    @keyframes cardIn{
      from{opacity:0;transform:translateY(18px) scale(.97)}
      to{opacity:1;transform:translateY(0) scale(1)}
    }
    .badge{
      display:inline-flex;align-items:center;gap:6px;
      background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.22);
      border-radius:99px;padding:4px 12px;font-size:.68rem;font-weight:600;
      color:#f87171;letter-spacing:.1em;text-transform:uppercase;margin-bottom:28px;
    }
    .dot{
      width:5px;height:5px;background:#ef4444;border-radius:50%;
      box-shadow:0 0 6px #ef4444;animation:pulse 1.8s ease-in-out infinite;
    }
    @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
    .shield{
      width:72px;height:72px;margin:0 auto 22px;
      background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.18);
      border-radius:18px;display:flex;align-items:center;justify-content:center;
      animation:glow 2.4s ease-in-out infinite;
    }
    @keyframes glow{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}50%{box-shadow:0 0 22px 4px rgba(239,68,68,.15)}}
    .shield svg{width:36px;height:36px}
    .title{
      font-weight:800;font-size:1.65rem;letter-spacing:-.01em;
      color:#fff;line-height:1.15;margin-bottom:10px;
    }
    .title span{color:#ef4444}
    .sub{font-size:.8rem;color:rgba(255,255,255,.35);line-height:1.6;margin-bottom:28px}
    .divider{width:100%;height:1px;background:rgba(255,255,255,.06);margin-bottom:24px}
    .warn{
      background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.16);
      border-radius:10px;padding:14px 18px;font-size:.73rem;
      color:rgba(255,150,150,.85);line-height:1.75;
    }
    .warn strong{color:#fca5a5;font-weight:600}
    .foot{
      margin-top:22px;font-size:.65rem;color:rgba(255,255,255,.15);
      letter-spacing:.04em;font-family:${fonts.mono};
    }
  </style>
</head>
<body oncontextmenu="return false">
  <div class="card">
    <div style="display:flex;justify-content:center">
      <div class="badge"><div class="dot"></div>${page.badge}</div>
    </div>
    <div class="shield">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
              fill="rgba(239,68,68,0.12)" stroke="#ef4444" stroke-width="1.5" stroke-linejoin="round"/>
        <line x1="9" y1="12" x2="11" y2="14" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="11" y1="14" x2="15" y2="10" stroke="#ef4444" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="title">${page.heading.prefix} <span>${page.heading.highlight}</span></div>
    <div class="sub">${subtitleHtml}</div>
    <div class="divider"></div>
    <div class="warn"><strong>${page.warning.bold}</strong><br/>${warningLinesHtml}</div>
    <div class="foot">${page.footer}</div>
  </div>
  <script>
    document.addEventListener('keydown',e=>{
      if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||(e.ctrlKey&&e.key==='U'))
        e.preventDefault();
    });
  <\/script>
</body>
</html>`;
}
