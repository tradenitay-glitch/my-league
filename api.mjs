// שרת קטן לאתר הליגה: שומר את כל הנתונים ב-Netlify Blobs.
// קריאה פתוחה לכולם, כתיבה רק עם סיסמת האדמין (משתנה סביבה ADMIN_PASSWORD).
import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

const KEY = "league";
const MAX_BYTES = 4 * 1024 * 1024;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readPassword() {
  try {
    const v = globalThis.Netlify?.env?.get?.("ADMIN_PASSWORD");
    if (v) return v;
  } catch {}
  return process.env.ADMIN_PASSWORD || "";
}

export function checkPassword(given, real) {
  if (!real) return { ok: false, reason: "no-password-set" };
  const a = createHash("sha256").update(String(given ?? "")).digest();
  const b = createHash("sha256").update(String(real)).digest();
  return { ok: timingSafeEqual(a, b) };
}

function validData(d) {
  return (
    d && typeof d === "object" && !Array.isArray(d) &&
    Array.isArray(d.teams) && Array.isArray(d.players) && Array.isArray(d.games) &&
    d.league && typeof d.league === "object"
  );
}

// makeHandler מקבל store כדי שאפשר יהיה לבדוק את הקוד בלי Netlify
export function makeHandler(openStore, getRealPassword = readPassword) {
  return async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const store = openStore();

    if (path.endsWith("/api/data") && req.method === "GET") {
      const doc = await store.get(KEY, { type: "json" });
      return json(doc || { data: null, rev: 0 });
    }

    if (path.endsWith("/api/login") && req.method === "POST") {
      let body = {};
      try { body = await req.json(); } catch {}
      const res = checkPassword(body.password, getRealPassword());
      if (res.reason === "no-password-set") return json({ ok: false, error: "no-password-set" }, 500);
      if (!res.ok) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }
      return json({ ok: true });
    }

    if (path.endsWith("/api/data") && (req.method === "PUT" || req.method === "POST")) {
      const res = checkPassword(req.headers.get("x-admin-password"), getRealPassword());
      if (res.reason === "no-password-set") return json({ ok: false, error: "no-password-set" }, 500);
      if (!res.ok) { await sleep(600); return json({ ok: false, error: "wrong-password" }, 401); }

      const text = await req.text();
      if (text.length > MAX_BYTES) return json({ ok: false, error: "too-big" }, 413);
      let body;
      try { body = JSON.parse(text); } catch { return json({ ok: false, error: "bad-json" }, 400); }
      if (!validData(body.data)) return json({ ok: false, error: "bad-data" }, 400);

      const current = (await store.get(KEY, { type: "json" })) || { data: null, rev: 0 };
      if (!body.force && Number(body.baseRev) !== Number(current.rev)) {
        return json({ ok: false, error: "conflict", current }, 409);
      }
      const doc = { data: body.data, rev: Number(current.rev) + 1, savedAt: new Date().toISOString() };
      await store.setJSON(KEY, doc);
      return json({ ok: true, rev: doc.rev, savedAt: doc.savedAt });
    }

    return json({ ok: false, error: "not-found" }, 404);
  };
}

export default makeHandler(() => getStore({ name: "league-data", consistency: "strong" }));

export const config = { path: ["/api/data", "/api/login"] };
