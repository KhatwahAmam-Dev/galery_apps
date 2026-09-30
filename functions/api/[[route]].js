// Cloudflare Pages Function: API Galeri Aplikasi
// Letak file : functions/api/[[route]].js  (menangani semua alamat /api/...)
// Binding KV : APPS
// Secret     : ADMIN_USER, ADMIN_PASS, SESSION_SECRET
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function sign(s, k) {
  const key = await crypto.subtle.importKey("raw", enc.encode(k), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", key, enc.encode(s)));
}
// Bandingkan lewat HMAC agar waktu pemeriksaan tidak membocorkan isi
const same = async (a, b, k) => (await sign(a, k)) === (await sign(b, k));
const send = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" } });

export async function onRequest({ request: req, env }) {
  const path = new URL(req.url).pathname, S = env.SESSION_SECRET;

  // Publik: baca daftar aplikasi
  if (path === "/api/apps" && req.method === "GET")
    return send(JSON.parse((await env.APPS.get("list")) || "null"));

  // Login admin (5 kali salah = diblokir 15 menit per alamat IP)
  if (path === "/api/login" && req.method === "POST") {
    const k = "fail:" + (req.headers.get("CF-Connecting-IP") || "x");
    const n = +((await env.APPS.get(k)) || 0);
    if (n >= 5) return send({ error: "blocked" }, 429);
    let b = {};
    try { b = await req.json(); } catch {}
    const u = await same(String(b.user || ""), env.ADMIN_USER, S);
    const p = await same(String(b.pass || ""), env.ADMIN_PASS, S);
    if (!(u && p)) {
      await env.APPS.put(k, String(n + 1), { expirationTtl: 900 });
      return send({ error: "invalid" }, 401);
    }
    const exp = String(Date.now() + 12 * 3600 * 1000);
    return send({ token: exp + "." + (await sign(exp, S)) });
  }

  // Admin: simpan daftar aplikasi
  if (path === "/api/apps" && req.method === "PUT") {
    const [exp, sig] = (req.headers.get("Authorization") || "").replace("Bearer ", "").split(".");
    if (!exp || !sig || +exp < Date.now() || sig !== (await sign(exp, S))) return send({ error: "unauthorized" }, 401);
    let d;
    try { d = await req.json(); } catch { return send({ error: "bad" }, 400); }
    if (!Array.isArray(d) || d.length > 200) return send({ error: "bad" }, 400);
    await env.APPS.put("list", JSON.stringify(d));
    return send({ ok: true });
  }
  return send({ error: "not found" }, 404);
}
