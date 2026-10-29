// English Steps / Ступени английского — server with accounts and progress storage
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_DAYS = 60;
const SCHEMA = (process.env.DB_SCHEMA || "public").replace(/[^a-z0-9_]/gi, "");
const q = (name) => `"${SCHEMA}".${name}`;

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.PGSSL === "1" ? { rejectUnauthorized: false } : false,
      max: 5,
      idleTimeoutMillis: 20000,
      connectionTimeoutMillis: 15000,
      keepAlive: true,
    })
  : null;
// An idle connection dropped by the database must not crash the server
if (pool) pool.on("error", (e) => console.error("DB pool error:", e.message));
process.on("unhandledRejection", (e) => console.error("Unhandled rejection:", e && e.message ? e.message : e));
process.on("uncaughtException", (e) => console.error("Uncaught exception:", e && e.stack ? e.stack : e));

async function migrate() {
  if (!pool) return;
  const ex = await pool.query("SELECT 1 FROM information_schema.schemata WHERE schema_name = $1", [SCHEMA]);
  if (!ex.rowCount) await pool.query(`CREATE SCHEMA "${SCHEMA}"`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${q("users")} (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON ${q("users")} (lower(username));
    CREATE TABLE IF NOT EXISTS ${q("sessions")} (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ${q("users")}(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ${q("progress")} (
      user_id INTEGER PRIMARY KEY REFERENCES ${q("users")}(id) ON DELETE CASCADE,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    ALTER TABLE ${q("users")} ALTER COLUMN password_hash DROP NOT NULL;
    ALTER TABLE ${q("users")} ADD COLUMN IF NOT EXISTS google_sub TEXT;
    ALTER TABLE ${q("users")} ADD COLUMN IF NOT EXISTS telegram_id BIGINT;
    ALTER TABLE ${q("users")} ADD COLUMN IF NOT EXISTS email TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub ON ${q("users")} (google_sub) WHERE google_sub IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_id ON ${q("users")} (telegram_id) WHERE telegram_id IS NOT NULL;
  `);
  await pool.query(`DELETE FROM ${q("sessions")} WHERE expires_at < now()`);
}

const app = express();
// Every async route: errors go to the error handler instead of crashing the process
for (const m of ["get", "post", "put", "delete"]) {
  const orig = app[m].bind(app);
  app[m] = (path, ...handlers) => (handlers.length === 0 ? orig(path)
    : orig(path, ...handlers.map((h) => (typeof h === "function" && h.length < 4 ? (req, res, next) => {
        try { const r = h(req, res, next); if (r && typeof r.catch === "function") r.catch(next); } catch (e) { next(e); }
      } : h))));
}
app.set("trust proxy", 1);
// When the site has moved, send every visitor to the new address
if (process.env.REDIRECT_TO) {
  const target = process.env.REDIRECT_TO.replace(/\/$/, "");
  app.use((req, res, next) => {
    if (req.path === "/api/health") return res.json({ ok: true, moved: target });
    res.redirect(301, target + req.originalUrl);
  });
}
app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" }));
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("X-Frame-Options", "SAMEORIGIN");
  next();
});

// --- helpers ---
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setSession(req, res, token) {
  const secure = req.secure ? "; Secure" : "";
  res.set("Set-Cookie", `sid=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`);
}
function clearSession(res) {
  res.set("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}
async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query(`INSERT INTO ${q("sessions")} (token, user_id, expires_at) VALUES ($1, $2, now() + $3::interval)`, [
    token, userId, `${SESSION_DAYS} days`,
  ]);
  return token;
}
async function currentUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return null;
  const r = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.created_at, u.google_sub, u.telegram_id FROM ${q("sessions")} s JOIN ${q("users")} u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > now()`, [sid]);
  return r.rows[0] || null;
}
async function getProgress(userId) {
  const r = await pool.query(`SELECT data FROM ${q("progress")} WHERE user_id = $1`, [userId]);
  return r.rows[0] ? r.rows[0].data : null;
}
const publicUser = (u) => ({ username: u.username, display_name: u.display_name, created_at: u.created_at,
  provider: u.google_sub ? "google" : u.telegram_id ? "telegram" : "password" });

// simple in-memory rate limit for auth endpoints
const hits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 10 * 60 * 1000)) hits.delete(k); }, 10 * 60 * 1000).unref();
function limited(req) {
  const key = req.ip + req.path;
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 10 * 60 * 1000);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > 20;
}
async function needDb(req, res, next) {
  for (let i = 0; pool && !dbReady && i < 16; i++) await new Promise((r) => setTimeout(r, 500));
  if (pool && !dbReady) return res.status(503).json({ error: "База данных запускается, попробуйте через минуту / Database is starting, try again in a minute" });
  if (!pool) return res.status(503).json({ error: "Database is not configured" });
  next();
}

// --- routes ---
app.get("/api/health", async (req, res) => {
  let db = false;
  if (pool && dbReady) { try { await pool.query("SELECT 1"); db = true; } catch (e) { db = false; } }
  res.json({ ok: true, db, time: new Date().toISOString() });
});

app.post("/api/register", needDb, async (req, res) => {
  if (limited(req)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const display_name = String(req.body.display_name || "").trim().slice(0, 40) || null;
  if (!/^[A-Za-z0-9_.\-а-яА-ЯёЁ]{3,32}$/.test(username))
    return res.status(400).json({ error: "Логин: 3–32 символа, буквы, цифры, _ . - / Username: 3–32 letters, digits, _ . -" });
  if (password.length < 6 || password.length > 200)
    return res.status(400).json({ error: "Пароль от 6 символов / Password needs 6+ characters" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO ${q("users")} (username, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id, username, display_name, created_at, google_sub, telegram_id`,
      [username, hash, display_name]);
    const user = r.rows[0];
    await pool.query(`INSERT INTO ${q("progress")} (user_id, data) VALUES ($1, '{}'::jsonb) ON CONFLICT DO NOTHING`, [user.id]);
    setSession(req, res, await createSession(user.id));
    res.json({ user: publicUser(user), progress: null });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Такой логин уже занят / Username is taken" });
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", needDb, async (req, res) => {
  if (limited(req)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const r = await pool.query(`SELECT id, username, display_name, password_hash, created_at, google_sub, telegram_id FROM ${q("users")} WHERE lower(username) = lower($1)`, [username]);
  const user = r.rows[0];
  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: "Неверный логин или пароль / Wrong username or password" });
  setSession(req, res, await createSession(user.id));
  res.json({ user: publicUser(user), progress: await getProgress(user.id) });
});

app.post("/api/logout", needDb, async (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) await pool.query(`DELETE FROM ${q("sessions")} WHERE token = $1`, [sid]).catch(() => {});
  clearSession(res);
  res.json({ ok: true });
});

app.get("/api/me", needDb, async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.json({ user: null });
  res.json({ user: publicUser(user), progress: await getProgress(user.id) });
});

app.put("/api/profile", needDb, async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  const name = String(req.body.display_name || "").trim().slice(0, 40) || null;
  const r = await pool.query(`UPDATE ${q("users")} SET display_name = $1 WHERE id = $2 RETURNING id, username, display_name, created_at, google_sub, telegram_id`, [name, user.id]);
  res.json({ user: publicUser(r.rows[0]) });
});

app.put("/api/progress", needDb, async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  const p = req.body && req.body.progress;
  if (!p || typeof p !== "object" || Array.isArray(p)) return res.status(400).json({ error: "Bad progress" });
  const cur = (await getProgress(user.id)) || {};
  const ex = {};
  const inEx = p.ex && typeof p.ex === "object" ? p.ex : {};
  for (const k of new Set([...Object.keys(cur.ex || {}), ...Object.keys(inEx)])) {
    if (k.length > 60) continue;
    const a = (cur.ex || {})[k] || {}, b = inEx[k] || {};
    ex[k] = {};
    for (const i of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!/^\d{1,3}$/.test(i)) continue;
      ex[k][i] = a[i] === true || b[i] === true ? true : (b[i] !== undefined ? !!b[i] : !!a[i]);
    }
  }
  const hw = Object.assign({}, cur.hw || {});
  for (const [k, v] of Object.entries(p.hw && typeof p.hw === "object" ? p.hw : {})) if (k.length <= 80) hw[k] = !!v;
  const data = { ex, hw,
    test: typeof p.test === "string" ? p.test.slice(0, 4) : (cur.test || null),
    skin: typeof p.skin === "string" ? p.skin.slice(0, 16) : (cur.skin || null) };
  await pool.query(
    `INSERT INTO ${q("progress")} (user_id, data, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, [user.id, data]);
  res.json({ ok: true, progress: data });
});


// --- social login (Google, Telegram) ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_BOT_NAME = (process.env.TELEGRAM_BOT_NAME || "").replace(/^@/, "");

app.get("/api/config", (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID || null, telegramBot: TELEGRAM_BOT_TOKEN && TELEGRAM_BOT_NAME ? TELEGRAM_BOT_NAME : null });
});

async function uniqueUsername(base) {
  let b = String(base || "user").toLowerCase().replace(/[^a-z0-9_.\-а-яё]/gi, "").slice(0, 24) || "user";
  if (b.length < 3) b = b + "_user";
  for (let i = 0; i < 20; i++) {
    const cand = i === 0 ? b : `${b}${Math.floor(1000 + Math.random() * 9000)}`;
    const r = await pool.query(`SELECT 1 FROM ${q("users")} WHERE lower(username) = lower($1)`, [cand]);
    if (!r.rowCount) return cand;
  }
  return `${b}${crypto.randomBytes(3).toString("hex")}`;
}
async function socialLogin(req, res, field, value, info) {
  let r = await pool.query(`SELECT id, username, display_name, created_at, google_sub, telegram_id FROM ${q("users")} WHERE ${field} = $1`, [value]);
  let user = r.rows[0];
  if (!user) {
    const username = await uniqueUsername(info.usernameBase);
    r = await pool.query(
      `INSERT INTO ${q("users")} (username, password_hash, display_name, ${field}, email) VALUES ($1, NULL, $2, $3, $4) RETURNING id, username, display_name, created_at, google_sub, telegram_id`,
      [username, (info.displayName || "").slice(0, 40) || null, value, info.email || null]);
    user = r.rows[0];
    await pool.query(`INSERT INTO ${q("progress")} (user_id, data) VALUES ($1, '{}'::jsonb) ON CONFLICT DO NOTHING`, [user.id]);
  }
  setSession(req, res, await createSession(user.id));
  res.json({ user: publicUser(user), progress: await getProgress(user.id) });
}

app.post("/api/auth/google", needDb, async (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(503).json({ error: "Google login is not configured" });
  if (limited(req)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const credential = String(req.body.credential || "");
  if (!credential || credential.length > 5000) return res.status(400).json({ error: "Bad credential" });
  try {
    const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential));
    const t = await r.json();
    if (!r.ok || t.aud !== GOOGLE_CLIENT_ID || !["accounts.google.com", "https://accounts.google.com"].includes(t.iss) || !t.sub)
      return res.status(401).json({ error: "Google не подтвердил вход / Google sign-in failed" });
    if (Number(t.exp) * 1000 < Date.now()) return res.status(401).json({ error: "Token expired" });
    const email = t.email_verified === "true" || t.email_verified === true ? t.email : null;
    await socialLogin(req, res, "google_sub", t.sub, {
      usernameBase: email ? email.split("@")[0] : t.given_name, displayName: t.given_name || t.name, email });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/telegram", needDb, async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(503).json({ error: "Telegram login is not configured" });
  if (limited(req)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const d = req.body || {};
  const hash = String(d.hash || "");
  const fields = ["auth_date", "first_name", "id", "last_name", "photo_url", "username"]
    .filter((k) => d[k] !== undefined && d[k] !== null && d[k] !== "")
    .map((k) => `${k}=${d[k]}`).sort().join("\n");
  const secret = crypto.createHash("sha256").update(TELEGRAM_BOT_TOKEN).digest();
  const check = crypto.createHmac("sha256", secret).update(fields).digest("hex");
  const okHash = hash.length === check.length && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(check));
  if (!okHash) return res.status(401).json({ error: "Telegram не подтвердил вход / Telegram sign-in failed" });
  if (Date.now() / 1000 - Number(d.auth_date) > 86400) return res.status(401).json({ error: "Login expired, try again" });
  await socialLogin(req, res, "telegram_id", Number(d.id), {
    usernameBase: d.username || d.first_name, displayName: d.first_name });
});

// --- Telegram Mini App (open the site inside the bot) ---
const SITE_URL = (process.env.SITE_URL || process.env.RENDER_EXTERNAL_URL || "").replace(/\/$/, "");
const TG_SECRET = TELEGRAM_BOT_TOKEN ? crypto.createHash("sha256").update("wh" + TELEGRAM_BOT_TOKEN).digest("hex").slice(0, 32) : "";

app.post("/api/auth/telegram-webapp", needDb, async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(503).json({ error: "Telegram is not configured" });
  const initData = String(req.body.initData || "");
  if (!initData || initData.length > 4096) return res.status(400).json({ error: "Bad data" });
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  params.delete("hash");
  const dcs = [...params.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
  const secret = crypto.createHmac("sha256", "WebAppData").update(TELEGRAM_BOT_TOKEN).digest();
  const check = crypto.createHmac("sha256", secret).update(dcs).digest("hex");
  if (hash.length !== check.length || !crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(check)))
    return res.status(401).json({ error: "Telegram не подтвердил вход / Telegram sign-in failed" });
  if (Date.now() / 1000 - Number(params.get("auth_date")) > 86400) return res.status(401).json({ error: "Session expired, reopen the app" });
  let u; try { u = JSON.parse(params.get("user") || "{}"); } catch (e) { u = {}; }
  if (!u.id) return res.status(400).json({ error: "No user" });
  await socialLogin(req, res, "telegram_id", Number(u.id), { usernameBase: u.username || u.first_name, displayName: u.first_name });
});

async function tg(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) console.error("Telegram", method, j.description || r.status);
  return j;
}
function openButton(text) { return { inline_keyboard: [[{ text, web_app: { url: SITE_URL } }]] }; }

app.post("/api/tg/webhook", async (req, res) => {
  if (!TG_SECRET || req.get("X-Telegram-Bot-Api-Secret-Token") !== TG_SECRET) return res.sendStatus(403);
  res.json({ ok: true });
  const m = req.body && req.body.message;
  if (!m || !m.chat) return;
  const name = (m.from && m.from.first_name) || "";
  const ru = !m.from || !m.from.language_code || m.from.language_code.startsWith("ru") || m.from.language_code.startsWith("kk");
  const text = ru
    ? `Привет${name ? ", " + name : ""}! 💗\n\n«Ступени английского» — английский от A1 до C1: грамматика, упражнения с проверкой, домашка и видео с вопросами.\n\nНажми кнопку ниже, чтобы открыть приложение. Прогресс сохраняется автоматически.`
    : `Hi${name ? ", " + name : ""}! 💗\n\nEnglish Steps — English from A1 to C1: grammar, self-checking exercises, homework and videos with questions.\n\nTap the button below to open the app. Your progress is saved automatically.`;
  tg("sendMessage", { chat_id: m.chat.id, text, reply_markup: openButton(ru ? "💗 Открыть приложение" : "💗 Open the app") }).catch(() => {});
});

async function setupTelegramBot() {
  if (!TELEGRAM_BOT_TOKEN || !SITE_URL) return;
  try {
    await tg("setChatMenuButton", { menu_button: { type: "web_app", text: "Открыть", web_app: { url: SITE_URL } } });
    await tg("setMyCommands", { commands: [{ command: "start", description: "Открыть приложение / Open the app" }] });
    await tg("setMyShortDescription", { short_description: "Английский от A1 до C1 — уроки, упражнения, видео 💗" });
    await tg("setMyDescription", { description: "Ступени английского: грамматика, упражнения с проверкой, домашние задания и видео с вопросами для уровней A1–C1. Нажмите «Открыть», чтобы начать." });
    await tg("setWebhook", { url: `${SITE_URL}/api/tg/webhook`, secret_token: TG_SECRET, allowed_updates: ["message"], drop_pending_updates: true });
    console.log("Telegram bot configured for", SITE_URL);
    setInterval(async () => {   // re-check every 30 minutes that the bot still points to this site
      try {
        const info = await tg("getWebhookInfo", {});
        const want = `${SITE_URL}/api/tg/webhook`;
        if (info.ok && info.result && info.result.url !== want) {
          console.log("Telegram webhook was", info.result.url, "- restoring");
          await tg("setWebhook", { url: want, secret_token: TG_SECRET, allowed_updates: ["message"] });
          await tg("setChatMenuButton", { menu_button: { type: "web_app", text: "Открыть", web_app: { url: SITE_URL } } });
        }
      } catch (e) {}
    }, 30 * 60 * 1000).unref();
  } catch (e) { console.error("Telegram setup failed, retrying in 1 min:", e.message); setTimeout(setupTelegramBot, 60000); }
}

app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));
app.get("/privacy", (req, res) => res.sendFile(path.join(__dirname, "public", "privacy.html")));
app.get("/terms", (req, res) => res.sendFile(path.join(__dirname, "public", "terms.html")));
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "7d",
  setHeaders: (res, file) => {
    if (/\.(html|webmanifest)$/.test(file) || file.endsWith("sw.js")) res.set("Cache-Control", "no-cache");
  },
}));
app.get("*", (req, res) => { res.set("Cache-Control", "no-cache"); res.sendFile(path.join(__dirname, "public", "index.html")); });
app.use((err, req, res, next) => {
  console.error("Request error:", req.method, req.path, err && err.message);
  if (res.headersSent) return;
  const dbDown = err && (/ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ECONNRESET|timeout|terminat|Connection/i.test(String(err.code) + " " + err.message));
  res.status(err && err.type === "entity.too.large" ? 413 : dbDown ? 503 : 500)
    .json({ error: dbDown ? "База данных временно недоступна, попробуйте через минуту / Database is temporarily unavailable" : "Ошибка сервера, попробуйте ещё раз / Server error, try again" });
});

let dbReady = false, migrateTries = 0;
async function migrateWithRetry() {
  if (!pool) return;
  try { await migrate(); dbReady = true; console.log("Database ready"); await require("./copy")(pool, SCHEMA); }
  catch (e) { migrateTries++; const wait = migrateTries < 6 ? 5000 : 30000; console.error(`Database not ready, retrying in ${wait / 1000}s:`, e.message); setTimeout(migrateWithRetry, wait); }
}
const server = app.listen(PORT, () => {
  console.log(`English Steps listening on ${PORT} (db: ${pool ? "on" : "off"})`);
  migrateWithRetry();
  if (!process.env.REDIRECT_TO) setupTelegramBot();
});

process.on("SIGTERM", () => {
  server.close(() => { (pool ? pool.end() : Promise.resolve()).finally(() => process.exit(0)); });
  setTimeout(() => process.exit(0), 8000).unref();
});
