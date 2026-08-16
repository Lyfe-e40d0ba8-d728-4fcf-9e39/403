// api/loader.js
// ══════════════════════════════════════════════════════════════════════════
//  FLYCER LOADER REGISTRY
//  Tambah / hapus loader di sini. Tidak perlu edit file lain.
// ══════════════════════════════════════════════════════════════════════════

export const LOADERS = {

  // ── Format key: "vX/namaUnik" ──────────────────────────────────────────
  // key   : digunakan di URL → /loaders/v2/ae3a52604adf
  // url   : raw URL script Lua yang akan di-load executor
  // active: false = return 403, true = aktif
  // note  : deskripsi (tidak dikirim ke client)

  "v2/ae3a52604adf": {
    url:    "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/supported-b045ccea-1f23-4201-866b-0b3c3381cdba/main/CarControllerUniversal",
    active: false,
    note:   "Car Controller for Mobile Universal",
  },

  "v2/af540ea0725a": {
    url:    "https://raw.githubusercontent.com/Iamnewcodethis2/RobeatsRevamp/main/233/RoBeatsV2.04/Main.lua",
    active: true,
    note:   "Script milik Maxwell - RobeatsRevamp",
  },

  "v3/premium": {
    url:    "https://raw.githubusercontent.com/user/repo/main/premium.lua",
    active: false,
    note:   "Premium script (inactive - placeholder)",
  },

};
