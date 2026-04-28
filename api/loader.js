// ══════════════════════════════════════════════════════════════════════════
//  LOADER REGISTRY
//  Edit file ini untuk menambah / menghapus loader.
//
//  Format:
//    "version/name": {
//      url: "https://...",       ← URL script Lua asli
//      active: true,             ← false = nonaktifkan tanpa hapus
//      note: "...",              ← opsional, keterangan
//    }
//
//  Akses di executor:
//    loadstring(game:HttpGet("https://flycer.my.id/loaders/v2/kyoukara"))()
// ══════════════════════════════════════════════════════════════════════════

export const LOADERS = {

  "v2/kyoukara": {
    url:    "https://raw.githubusercontent.com/Lyfe-e40d0ba8-d728-4fcf-9e39/Main/refs/heads/main/Test",
    active: true,
    note:   "Main loader v2",
  },

  // ── Tambah loader baru di bawah ini ──────────────────────────────────

  // "v2/script2": {
  //   url:    "https://raw.githubusercontent.com/user/repo/main/script2.lua",
  //   active: true,
  //   note:   "Script tambahan",
  // },

  // "v3/premium": {
  //   url:    "https://raw.githubusercontent.com/user/repo/main/premium.lua",
  //   active: true,
  //   note:   "Premium only",
  // },

  // "v1/legacy": {
  //   url:    "https://raw.githubusercontent.com/user/repo/main/legacy.lua",
  //   active: false,   ← nonaktif, tidak bisa diakses
  //   note:   "Deprecated",
  // },

};
