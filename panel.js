export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const host = url.hostname;

    if (!env.DB) {
      return new Response(
        "خطا: دیتابیس D1 متصل نشده است.",
        { status: 500 }
      );
    }

    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT
        )
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT UNIQUE,
          uuid TEXT,
          protocol TEXT,
          traffic TEXT,
          expire TEXT,
          port TEXT,
          tls TEXT,
          adblock TEXT,
          adult_block TEXT,
          status TEXT,
          created_at TEXT,
          sub_token TEXT
        )
      `).run();

      const columns = await env.DB
        .prepare("PRAGMA table_info(users)")
        .all();

      const names = new Set(
        (columns.results || []).map(column => column.name)
      );

      const migrations = [
        ["created_at", "TEXT"],
        ["sub_token", "TEXT"],
        ["tls", "TEXT"],
        ["adblock", "TEXT"],
        ["adult_block", "TEXT"]
      ];

      for (const [name, type] of migrations) {
        if (!names.has(name)) {
          await env.DB
            .prepare(`ALTER TABLE users ADD COLUMN ${name} ${type}`)
            .run();
        }
      }
    } catch (error) {
      return json({
        success: false,
        error: "خطای آماده‌سازی دیتابیس",
        detail: String(error.message || error)
      }, 500);
    }

    // احراز هویت مدیریت برای روت و مسیرهای API
    if (path === "/" || path.startsWith("/api/")) {
      const adminUser = env.ADMIN_USER;
      const adminPass = env.ADMIN_PASSWORD;

      if (!adminUser || !adminPass) {
        return new Response(
          "متغیرهای ADMIN_USER و ADMIN_PASSWORD را تنظیم کن.",
          { status: 500 }
        );
      }

      const auth = request.headers.get("Authorization") || "";

      if (!auth.startsWith("Basic ")) {
        return new Response("Authentication required", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Basic realm="KINGAMIR PANEL"'
          }
        });
      }

      try {
        const decoded = atob(auth.slice(6));
        const index = decoded.indexOf(":");

        if (
          index < 0 ||
          decoded.slice(0, index) !== adminUser ||
          decoded.slice(index + 1) !== adminPass
        ) {
          return new Response("Invalid credentials", {
            status: 401
          });
        }
      } catch {
        return new Response("Invalid authentication encoding", {
          status: 400
        });
      }
    }

    const activeRow = await env.DB
      .prepare(
        "SELECT value FROM settings WHERE key = 'clean_ip'"
      )
      .first()
      .catch(() => null);

    const activeCleanIp = activeRow?.value || host;

    // هدایت مسیرهای API کاربران
    if (path.startsWith("/api/users")) {
      return await handleUserApi(request, env, path);
    }

    // مدیریت لینک‌های ساب‌سکریپشن عمومی کاربران
    if (path.startsWith("/sub/")) {
      const parts = path.split("/").filter(Boolean);
      // مسیر به صورت /sub/username/token است
      if (parts.length >= 3) {
        const username = decodeURIComponent(parts[1]);
        const token = decodeURIComponent(parts[2]);

        const user = await getPublicUser(env.DB, username, token);
        if (!user) {
          return new Response("اشتراک معتبر نیست یا غیرفعال است.", { status: 404 });
        }

        const port = Number(user.port || 443);
        const protocol = (user.protocol || "vless").toLowerCase();
        const uuid = user.uuid;
        const name = encodeURIComponent(user.username);
        let config = "";

        if (protocol === "vless") {
          config = `vless://${uuid}@${activeCleanIp}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(host)}&fp=chrome&type=ws&host=${encodeURIComponent(host)}&path=%2F%3Fed%3D2048#${name}`;
        } else if (protocol === "trojan") {
          config = `trojan://${uuid}@${activeCleanIp}:${port}?security=tls&sni=${encodeURIComponent(host)}&type=ws&host=${encodeURIComponent(host)}&path=%2F%3Fed%3D2048#${name}`;
        } else if (protocol === "ss" || protocol === "shadowsocks") {
          const auth = btoa(`chacha20-ietf-poly1305:${uuid}`);
          config = `ss://${auth}@${activeCleanIp}:${port}#${name}`;
        } else {
          return new Response("پروتکل پشتیبانی نمی‌شود.", { status: 400 });
        }

        return new Response(encodeBase64(config), {
          headers: {
            "Content-Type": "text/plain; charset=UTF-8",
            "Cache-Control": "no-store"
          }
        });
      }
    }

    // بازگرداندن صفحه داشبورد مدیریتی در روت
    return html(dashboard(host));
  }
};

// ========================================================
// DATABASE & USER MANAGEMENT HELPERS
// ========================================================

async function getUserByUsername(DB, username) {
  return await DB.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).bind(username).first();
}

async function getUserById(DB, id) {
  return await DB.prepare(
    "SELECT * FROM users WHERE id = ?"
  ).bind(id).first();
}

async function listUsers(DB) {
  const result = await DB.prepare(
    "SELECT * FROM users ORDER BY created_at DESC"
  ).all();

  return result.results || [];
}

async function createUser(DB, data) {
  const username = String(data.username || "").trim();
  const protocol = String(data.protocol || "vless").toLowerCase();
  const traffic = String(data.traffic || "10");
  const expire = String(data.expire || "30");
  const port = String(data.port || "443");

  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
    throw new Error("نام کاربری باید ۳ تا ۳۲ کاراکتر باشد.");
  }

  if (!["vless", "trojan", "ss"].includes(protocol)) {
    throw new Error("پروتکل معتبر نیست.");
  }

  if (!validPort(port)) {
    throw new Error("پورت معتبر نیست.");
  }

  if (!Number.isFinite(Number(traffic)) || Number(traffic) <= 0) {
    throw new Error("حجم ترافیک معتبر نیست.");
  }

  if (!Number.isFinite(Number(expire)) || Number(expire) <= 0) {
    throw new Error("مدت اعتبار معتبر نیست.");
  }

  const existing = await getUserByUsername(DB, username);

  if (existing) {
    throw new Error("این نام کاربری قبلاً ثبت شده است.");
  }

  const id = crypto.randomUUID();
  const uuid = crypto.randomUUID();
  const subToken = randomToken();
  const now = new Date().toISOString();

  await DB.prepare(`
    INSERT INTO users (
      id, username, uuid, protocol, traffic, expire,
      port, tls, adblock, adult_block, status,
      created_at, sub_token
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    username,
    uuid,
    protocol,
    traffic,
    expire,
    port,
    String(data.tls ?? "true"),
    String(data.adblock ?? "false"),
    String(data.adult_block ?? "false"),
    "active",
    now,
    subToken
  ).run();

  return await getUserById(DB, id);
}

async function deleteUser(DB, id) {
  const result = await DB.prepare(
    "DELETE FROM users WHERE id = ?"
  ).bind(id).run();

  return result.meta?.changes > 0;
}

async function setUserStatus(DB, id, status) {
  if (!["active", "disabled"].includes(status)) {
    throw new Error("وضعیت نامعتبر است.");
  }

  await DB.prepare(
    "UPDATE users SET status = ? WHERE id = ?"
  ).bind(status, id).run();

  return await getUserById(DB, id);
}

async function updateUserExpiry(DB, id, days) {
  const value = Number(days);

  if (!Number.isFinite(value) || value <= 0 || value > 3650) {
    throw new Error("مدت اعتبار باید بین ۱ تا ۳۶۵۰ روز باشد.");
  }

  const user = await getUserById(DB, id);

  if (!user) {
    throw new Error("کاربر پیدا نشد.");
  }

  await DB.prepare(
    "UPDATE users SET expire = ? WHERE id = ?"
  ).bind(String(value), id).run();

  return await getUserById(DB, id);
}

async function updateUserTraffic(DB, id, traffic) {
  const value = Number(traffic);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("حجم ترافیک معتبر نیست.");
  }

  const user = await getUserById(DB, id);

  if (!user) {
    throw new Error("کاربر پیدا نشد.");
  }

  await DB.prepare(
    "UPDATE users SET traffic = ? WHERE id = ?"
  ).bind(String(value), id).run();

  return await getUserById(DB, id);
}

async function getPublicUser(DB, username, token) {
  const user = await DB.prepare(`
    SELECT * FROM users
    WHERE username = ? AND sub_token = ?
  `).bind(username, token).first();

  if (!user || user.status !== "active") {
    return null;
  }

  const days = remainingDays(user.created_at, user.expire);

  if (days !== null && days <= 0) {
    return null;
  }

  return user;
}

// ========================================================
// VALIDATION, EXPIRY & SUBSCRIPTION HELPERS
// ========================================================

function validPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function remainingDays(createdAt, durationDays) {
  if (!createdAt || !Number.isFinite(Number(durationDays))) {
    return null;
  }

  const created = Date.parse(createdAt);

  if (!Number.isFinite(created)) {
    return null;
  }

  const expiry = created + Number(durationDays) * 86400000;
  return Math.ceil((expiry - Date.now()) / 86400000);
}

function isUserExpired(user) {
  const days = remainingDays(user.created_at, user.expire);
  return days !== null && days <= 0;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function encodeBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";

  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }

  return btoa(binary);
}

function encodeBase64Url(text) {
  return encodeBase64(text)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function safeHostname(value) {
  try {
    const url = new URL("https://" + value);

    if (
      url.hostname !== value ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function buildSubscriptionUrl(request, username, token) {
  const url = new URL(request.url);
  return `${url.origin}/sub/${encodeURIComponent(username)}/${encodeURIComponent(token)}`;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

async function requireJson(request) {
  const contentType = request.headers.get("content-type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("درخواست باید از نوع JSON باشد.");
  }

  const text = await request.text();

  if (text.length > 100000) {
    throw new Error("حجم درخواست بیش از حد مجاز است.");
  }

  try {
    const data = JSON.parse(text);

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error();
    }

    return data;
  } catch {
    throw new Error("JSON نامعتبر است.");
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function html(content) {
  return new Response(content, {
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function yamlEscape(value) {
  return JSON.stringify(String(value ?? ""));
}

function isValidIPv4(ip) {
  const parts = ip.split(".");

  if (parts.length !== 4) return false;

  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;

    const number = Number(part);

    return number >= 0 && number <= 255;
  });
}

function isValidIPv6(ip) {
  if (!ip || !ip.includes(":")) return false;
  if (!/^[0-9a-fA-F:]+$/.test(ip)) return false;
  if (ip.includes(":::")) return false;

  const halves = ip.split("::");

  if (halves.length > 2) return false;

  function countGroups(part) {
    if (!part) return 0;

    const groups = part.split(":");

    if (groups.some(group =>
      !/^[0-9a-fA-F]{1,4}$/.test(group)
    )) {
      return -1;
    }

    return groups.length;
  }

  const left = countGroups(halves[0]);

  if (left < 0) return false;

  if (halves.length === 1) {
    return left === 8;
  }

  const right = countGroups(halves[1]);

  if (right < 0) return false;

  return left + right < 8;
}

function isValidIp(ip) {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function makeIpKey(ip) {
  const bytes = new TextEncoder().encode(ip);

  return "ip_" + Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

// ========================================================
// USER API ROUTES HANDLER
// ========================================================

async function handleUserApi(request, env, path) {
  const DB = env.DB;
  const method = request.method;

  // GET /api/users
  if (path === "/api/users" && method === "GET") {
    const users = await listUsers(DB);

    return jsonResponse({
      ok: true,
      count: users.length,
      users: users.map(user => ({
        id: user.id,
        username: user.username,
        protocol: user.protocol,
        traffic: user.traffic,
        expire: user.expire,
        port: user.port,
        status: user.status,
        created_at: user.created_at,
        expired: isUserExpired(user),
        remaining_days: remainingDays(
          user.created_at,
          user.expire
        )
      }))
    });
  }

  // POST /api/users
  if (path === "/api/users" && method === "POST") {
    try {
      const data = await requireJson(request);
      const user = await createUser(DB, data);

      return jsonResponse({
        ok: true,
        message: "کاربر ساخته شد.",
        user: {
          id: user.id,
          username: user.username,
          protocol: user.protocol,
          status: user.status
        },
        subscription: buildSubscriptionUrl(
          request,
          user.username,
          user.sub_token
        )
      }, 201);
    } catch (e) {
      return jsonResponse({ ok: false, error: e.message }, 400);
    }
  }

  const match = path.match(/^\/api\/users\/([^/]+)(?:\/(status|expiry|traffic))?$/);

  if (!match) {
    return jsonResponse({
      ok: false,
      error: "مسیر API پیدا نشد."
    }, 404);
  }

  const id = decodeURIComponent(match[1]);
  const action = match[2];

  if (method === "DELETE" && !action) {
    const deleted = await deleteUser(DB, id);

    if (!deleted) {
      return jsonResponse({
        ok: false,
        error: "کاربر پیدا نشد."
      }, 404);
    }

    return jsonResponse({
      ok: true,
      message: "کاربر حذف شد."
    });
  }

  if (method === "PATCH" && action) {
    try {
      const data = await requireJson(request);
      let user;

      if (action === "status") {
        user = await setUserStatus(DB, id, data.status);
      } else if (action === "expiry") {
        user = await updateUserExpiry(DB, id, data.days);
      } else if (action === "traffic") {
        user = await updateUserTraffic(DB, id, data.traffic);
      }

      if (!user) {
        return jsonResponse({
          ok: false,
          error: "کاربر پیدا نشد."
        }, 404);
      }

      return jsonResponse({
        ok: true,
        message: "اطلاعات کاربر به‌روزرسانی شد.",
        user: {
          id: user.id,
          username: user.username,
          protocol: user.protocol,
          traffic: user.traffic,
          expire: user.expire,
          status: user.status
        }
      });
    } catch (e) {
      return jsonResponse({ ok: false, error: e.message }, 400);
    }
  }

  return jsonResponse({
    ok: false,
    error: "متد درخواست پشتیبانی نمی‌شود."
  }, 405);
}

// قالب پنل مدیریت (داشبورد HTML)
function dashboard(host) {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KINGAMIR PANEL</title>
<style>
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af;--green:#10b981;--red:#ef4444}
*{box-sizing:border-box}
body{margin:0;padding:15px;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif}
main{max-width:1100px;margin:auto}
header,.card,.toolbar{background:var(--card);border:1px solid var(--border);border-radius:15px;padding:17px;margin-bottom:15px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:21px;color:var(--gold);margin:0}
button{border:0;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:bold;background:var(--gold);color:#111}
.muted{color:var(--muted);font-size:12px}
</style>
</head>
<body>
<main>
<header>
  <h1>KINGAMIR PANEL - پنل مدیریت</h1>
  <div class="muted">میزبان: ${escapeHtml(host)}</div>
</header>
<section class="card">
  <h2>خوش آمدید!</h2>
  <p>ساختار دیتابیس، مسیرهای ساب‌سکریپشن و توابع مدیریت کاربران با موفقیت متصل و یکپارچه شدند.</p>
</section>
</main>
</body>
</html>`;
}
