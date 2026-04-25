import crypto from "crypto";

export default async function handler(req, res) {
  const { token, sig } = req.query;

  if (!token || !sig) {
    return res.status(403).send("-- invalid request");
  }

  const record = usedTokens.get(token);
  if (!record) {
    return res.status(403).send("-- token invalid");
  }

  // cek expire
  if (Date.now() > record.expiry) {
    usedTokens.delete(token);
    return res.status(403).send("-- expired");
  }

  // verify signature
  const payload = `${token}:${record.expiry}:${record.ip}`;
  const checkSig = crypto
    .createHmac("sha256", process.env.HMAC_SECRET)
    .update(payload)
    .digest("hex");

  if (sig !== checkSig) {
    return res.status(403).send("-- bad signature");
  }

  // 🔥 ambil script asli dari GitHub
  const scriptUrl = "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test";

  try {
    const r = await fetch(scriptUrl);
    const code = await r.text();

    // optional: obfuscate ringan
    const wrapped = `
-- secured payload
local _=${Math.random()}
${code}
`;

    // hapus token (one-time use)
    usedTokens.delete(token);

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(wrapped);

  } catch {
    return res.status(500).send("-- fetch failed");
  }
}
