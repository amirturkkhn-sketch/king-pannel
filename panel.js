export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const host = url.hostname;

    if (!env.DB) {
      return new Response("خطا: دیتابیس D1 متصل نشده است.", { status: 500 });
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
          username TEXT,
          uuid TEXT,
          protocol TEXT,
          traffic TEXT,
          expire TEXT,
          port TEXT,
          tls TEXT,
          adblock TEXT,
          adult_block TEXT,
          status TEXT
        )
      `).run();
    } catch (error) {
      return json({ success: false, error: "خطای آماده‌سازی دیتابیس." }, 500);
    }

    // -----------------------------------------------------
    // SECURE ADMIN AUTHENTICATION (NO HARDCODED FALLBACKS)
    // -----------------------------------------------------
    if (path.startsWith("/api/") || path === "/") {
      const adminUser = env.ADMIN_USER;
      const adminPass = env.ADMIN_PASSWORD;

      if (!adminUser || !adminPass) {
        return new Response(
          "خطای امنیتی: متغیرهای محیطی ADMIN_USER و ADMIN_PASSWORD تنظیم نشده‌اند.",
          { status: 500 }
        );
      }

      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Basic ")) {
        return new Response("Authentication required", {
          status: 401,
          headers: { "WWW-Authenticate": 'Basic realm="KINGAMIR PANEL"' }
        });
      }

      try {
        const base64Credentials = authHeader.split(" ")[1];
        const credentials = atob(base64Credentials);
        const colonIndex = credentials.indexOf(":");
        if (colonIndex === -1) {
          return new Response("Invalid credentials format", { status: 401 });
        }
        const username = credentials.slice(0, colonIndex);
        const password = credentials.slice(colonIndex + 1);

        if (username !== adminUser || password !== adminPass) {
          return new Response("Invalid credentials", { status: 401 });
        }
      } catch {
        return new Response("Invalid authentication encoding", { status: 400 });
      }
    }

    const activeRow = await env.DB
      .prepare("SELECT value FROM settings WHERE key = 'clean_ip'")
      .first()
      .catch(() => null);

    const activeCleanIp = activeRow?.value || host;

    // -----------------------------------------------------
    // SUBSCRIPTION: VLESS / TROJAN / SHADOWSOCKS
    // -----------------------------------------------------
    if ((path.startsWith("/sub/") || path.startsWith("/yaml/")) && method === "GET") {
      const username = decodeURIComponent(path.split("/")[2] || "");

      if (!username) {
        return new Response("Username required", { status: 400 });
      }

      const user = await env.DB
        .prepare("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (!user) {
        return new Response("User not found", { status: 404 });
      }

      if (user.status === "disabled") {
        return new Response("Subscription disabled", { status: 403 });
      }

      const port = Number(user.port || 443);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return new Response("Invalid port", { status: 500 });
      }

      const protocol = (user.protocol || "VLESS").toLowerCase();
      const name = encodeURIComponent(user.username);
      let config = "";

      if (protocol === "vless") {
        config =
          `vless://${user.uuid}@${activeCleanIp}:${port}` +
          `?encryption=none&security=tls` +
          `&sni=${encodeURIComponent(host)}` +
          `&fp=chrome&type=ws` +
          `&host=${encodeURIComponent(host)}` +
          `&path=%2F%3Fed%3D2048#${name}`;
      } else if (protocol === "trojan") {
        config =
          `trojan://${user.uuid}@${activeCleanIp}:${port}` +
          `?security=tls` +
          `&sni=${encodeURIComponent(host)}` +
          `&type=ws` +
          `&host=${encodeURIComponent(host)}` +
          `&path=%2F%3Fed%3D2048#${name}`;
      } else if (protocol === "shadowsocks" || protocol === "ss") {
        const auth = btoa(`chacha20-ietf-poly1305:${user.uuid}`);
        config = `ss://${auth}@${activeCleanIp}:${port}#${name}`;
      } else {
        return new Response("Unsupported protocol", { status: 400 });
      }

      if (path.startsWith("/yaml/")) {
        const yaml = [
          "proxies:",
          `  - name: "${yamlEscape(user.username)}"`,
          `    type: ${protocol}`,
          `    server: "${yamlEscape(activeCleanIp)}"`,
          `    port: ${port}`,
          protocol === "vless" ? `    uuid: "${user.uuid}"` : `    password: "${user.uuid}"`,
          protocol === "vless" ? "    encryption: none" : "",
          "    network: ws",
          "    tls: true",
          `    servername: "${yamlEscape(host)}"`,
          "    skip-cert-verify: false",
          "    ws-opts:",
          '      path: "/?ed=2048"',
          "      headers:",
          `        Host: "${yamlEscape(host)}"`
        ].filter(Boolean).join("\n");

        return new Response(yaml, {
          headers: {
            "Content-Type": "text/yaml; charset=UTF-8",
            "Cache-Control": "no-store"
          }
        });
      }

      return new Response(
        btoa(unescape(encodeURIComponent(config))),
        {
          headers: {
            "Content-Type": "text/plain; charset=UTF-8",
            "Cache-Control": "no-store"
          }
        }
      );
    }

    // -----------------------------------------------------
    // USER STATUS
    // -----------------------------------------------------
    if (path.startsWith("/status/") && method === "GET") {
      const username = decodeURIComponent(path.split("/")[2] || "");
      const user = await env.DB
        .prepare("SELECT username, status FROM users WHERE username = ?")
        .bind(username)
        .first();

      if (!user) {
        return new Response("کاربر پیدا نشد.", { status: 404 });
      }

      return html(`
        <!doctype html>
        <html lang="fa" dir="rtl">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>وضعیت اشتراک</title>
        <body style="background:#030508;color:#fff;font-family:sans-serif;padding:30px">
          <main style="max-width:480px;margin:auto;background:#0a0e17;padding:25px;border-radius:18px">
            <h2 style="color:#f59e0b">${escapeHtml(user.username)}</h2>
            <p>وضعیت حساب: ${user.status === "disabled" ? "غیرفعال" : "فعال"}</p>
          </main>
        </body>
        </html>
      `);
    }

    // -----------------------------------------------------
    // GET USERS AND SAVED IPS
    // -----------------------------------------------------
    if (path === "/api/users" && method === "GET") {
      const usersResult = await env.DB.prepare("SELECT * FROM users ORDER BY rowid DESC").all();
      const ipsResult = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'ip_%'").all();

      return json({
        success: true,
        users: usersResult.results || [],
        savedIps: (ipsResult.results || []).map(row => ({ id: row.key, ip: row.value })),
        activeCleanIp,
        metrics: {
          total: (usersResult.results || []).length,
          active: (usersResult.results || []).filter(u => u.status === 'active').length
        }
      });
    }

    // -----------------------------------------------------
    // ADD OR EDIT USER (قید پورت‌های امن کلودفلر)
    // -----------------------------------------------------
    if (path === "/api/users" && method === "POST") {
      const body = await readJson(request);
      if (!body) return json({ error: "اطلاعات ارسالی معتبر نیست." }, 400);

      const rawName = String(body.username || "").trim();
      if (!rawName) return json({ error: "نام کاربری الزامی است." }, 400);

      const username = rawName.toUpperCase().startsWith("👑KING_") ? rawName : "👑KING_" + rawName;
      const protocol = String(body.protocol || "VLESS");
      if (!["VLESS", "Trojan", "Shadowsocks"].includes(protocol)) {
        return json({ error: "پروتکل معتبر نیست." }, 400);
      }

      const port = String(body.port || "443");
      if (!["443", "2053", "2083", "2087", "8443"].includes(port)) {
        return json({ error: "پورت نامعتبر است. فقط پورت‌های پشتیبانی‌شده ابری مجاز هستند." }, 400);
      }

      const trafficNum = Number(body.traffic ?? 100);
      const expireNum = Number(body.expire ?? 30);
      if (!Number.isFinite(trafficNum) || trafficNum <= 0 || !Number.isFinite(expireNum) || expireNum <= 0) {
        return json({ error: "حجم و اعتبار باید اعداد مثبت باشند." }, 400);
      }

      const traffic = `${trafficNum} GB`;
      const expire = `${expireNum} روز`;
      const status = body.status === "disabled" ? "disabled" : "active";

      if (body.id) {
        const existingUser = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(String(body.id)).first();
        if (!existingUser) return json({ error: "کاربر مورد نظر یافت نشد." }, 404);

        await env.DB.prepare(`
          UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, status = ? WHERE id = ?
        `).bind(protocol, traffic, expire, port, status, String(body.id)).run();

        return json({ success: true, message: "کاربر ویرایش شد." });
      }

      const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
      if (existing) return json({ error: "این نام کاربری قبلاً ثبت شده است." }, 409);

      const id = "usr_" + crypto.randomUUID();
      const uuid = crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?)
      `).bind(id, username, uuid, protocol, traffic, expire, port, status).run();

      return json({ success: true, message: "کاربر ثبت شد." });
    }

    // -----------------------------------------------------
    // DELETE USER
    // -----------------------------------------------------
    if (path.startsWith("/api/users/") && method === "DELETE") {
      const id = decodeURIComponent(path.slice("/api/users/".length));
      if (!id) return json({ error: "شناسه نامعتبر است." }, 400);

      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
      return json({ success: true });
    }

    // -----------------------------------------------------
    // SET CLEAN IP (قید ساختاری آی‌پی)
    // -----------------------------------------------------
    if (path === "/api/set-clean-ip" && method === "POST") {
      const body = await readJson(request);
      const ip = String(body?.ip || "").trim();
      
      if (!isValidIp(ip)) {
        return json({ error: "قالب IP معتبر نیست." }, 400);
      }

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(makeIpKey(ip), ip).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();

      return json({ success: true, activeCleanIp: ip });
    }

    // -----------------------------------------------------
    // IMPORT IPS
    // -----------------------------------------------------
    if (path === "/api/import-ips" && method === "POST") {
      const body = await readJson(request);
      const rawIps = String(body?.ips || "");
      const input = [...new Set(rawIps.split(/[\s,;]+/).map(i => i.trim()).filter(Boolean))];

      if (input.length === 0 || input.length > 500) {
        return json({ error: "تعداد IPها باید بین ۱ تا ۵۰۰ باشد." }, 400);
      }

      const valid = input.filter(isValidIp);
      for (const ip of valid) {
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(makeIpKey(ip), ip).run();
      }

      return json({ success: true, saved: valid.length });
    }

    // -----------------------------------------------------
    // SELECT SAVED IP
    // -----------------------------------------------------
    if (path === "/api/select-clean-ip" && method === "POST") {
      const body = await readJson(request);
      const ip = String(body?.ip || "").trim();
      if (!isValidIp(ip)) return json({ error: "قالب IP معتبر نیست." }, 400);

      const saved = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(makeIpKey(ip)).first();
      if (!saved || saved.value !== ip) {
        return json({ error: "این IP در مخزن ذخیره نشده است." }, 404);
      }

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();
      return json({ success: true, activeCleanIp: ip });
    }

    // -----------------------------------------------------
    // DELETE SAVED IP
    // -----------------------------------------------------
    if (path.startsWith("/api/delete-ip/") && method === "DELETE") {
      const key = decodeURIComponent(path.slice("/api/delete-ip/".length));
      if (!/^ip_[a-zA-Z0-9_]+$/.test(key)) return json({ error: "کلید نامعتبر است." }, 400);

      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
      if (!row) return json({ error: "IP یافت نشد." }, 404);

      const active = await env.DB.prepare("SELECT value FROM settings WHERE key = 'clean_ip'").first();

      await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();

      if (active?.value === row.value) {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'clean_ip'").run();
      }

      return json({ success: true });
    }

    // -----------------------------------------------------
    // CLOUDFLARE RANGES
    // -----------------------------------------------------
    if (path === "/api/cloudflare-ranges" && method === "GET") {
      const [r4, r6] = await Promise.all([
        fetch("https://www.cloudflare.com/ips-v4"),
        fetch("https://www.cloudflare.com/ips-v6")
      ]);
      return json({
        success: true,
        ipv4: (await r4.text()).trim().split(/\s+/).filter(Boolean),
        ipv6: (await r6.text()).trim().split(/\s+/).filter(Boolean)
      });
    }

    return html(dashboard(host));
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=UTF-8", "Cache-Control": "no-store" }
  });
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

function html(content) {
  return new Response(content, {
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" }
  });
}

function escapeHtml(val) {
  return String(val ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

function yamlEscape(val) {
  return String(val ?? "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function isValidIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(ip) {
  if (!ip.includes(":") || !/^[0-9a-fA-F:]+$/.test(ip)) return false;
  if (ip.includes(":::")) return false;
  const halves = ip.split("::");
  if (halves.length > 2) return false;
  const count = s => (s ? s.split(":").length : 0);
  if (halves.length === 1) return count(ip) === 8;
  return count(halves[0]) + count(halves[1]) < 8;
}

function isValidIp(ip) {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function makeIpKey(ip) {
  return "ip_" + ip.replace(/[^a-zA-Z0-9]/g, "_");
}

function dashboard(host) {
  const safeHost = JSON.stringify(host);
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
header,.card,.toolbar,.box{background:var(--card);border:1px solid var(--border);border-radius:15px;padding:17px;margin-bottom:15px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:21px;color:var(--gold);margin:0}
h2{font-size:16px}
.muted{color:var(--muted);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:15px}
.stat{background:var(--card);border:1px solid var(--border);padding:16px;border-radius:12px}
.stat b{display:block;font-size:22px;color:var(--gold);margin-top:6px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap}
input,select,textarea{width:100%;padding:11px;background:var(--bg);color:white;border:1px solid var(--border);border-radius:9px;margin:5px 0 12px}
textarea{min-height:110px}
button,.button{border:0;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block;margin:3px}
.gold{background:var(--gold);color:#111}
.outline{background:#111827;color:white;border:1px solid var(--border)}
.danger{background:#451a1a;color:#fecaca}
.user{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:15px;margin:12px 0;overflow-wrap:anywhere}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.tag{font-size:12px;color:var(--green)}
.ip{padding:10px;border-bottom:1px solid var(--border);overflow-wrap:anywhere}
dialog{width:min(650px,95vw);max-height:90vh;overflow:auto;background:var(--card);color:white;border:1px solid var(--gold);border-radius:15px}
dialog::backdrop{background:#000b}
</style>
</head>
<body>
<main>
<header>
  <h1>KINGAMIR PANEL</h1>
  <div class="tag" id="active-ip">در حال دریافت IP فعال...</div>
</header>

<section class="stats">
  <div class="stat">تعداد کاربران<b id="total">0</b></div>
  <div class="stat">کاربران فعال<b id="active">0</b></div>
  <div class="stat">IPهای مخزن<b id="ip-total">0</b></div>
</section>

<div class="toolbar">
  <button class="gold" onclick="openUser()">+ ایجاد کاربر</button>
  <button class="outline" onclick="openIps()">مدیریت IPها</button>
  <button class="outline" onclick="loadAll()">بروزرسانی</button>
</div>

<section id="users"></section>

<dialog id="user-dialog">
  <h2 id="user-title">ایجاد کاربر</h2>
  <form id="user-form">
    <input id="edit-id" type="hidden">
    <label>نام کاربری</label>
    <input id="username" required placeholder="مثلاً ali">
    <label>پروتکل</label>
    <select id="protocol">
      <option>VLESS</option><option>Trojan</option><option>Shadowsocks</option>
    </select>
    <label>پورت</label>
    <select id="port">
      <option>443</option><option>2053</option><option>2083</option>
      <option>2087</option><option>8443</option>
    </select>
    <label>حجم (GB)</label><input id="traffic" type="number" min="1" value="100" required>
    <label>اعتبار (روز)</label><input id="expire" type="number" min="1" value="30" required>
    <label>وضعیت</label>
    <select id="status"><option value="active">فعال</option><option value="disabled">غیرفعال</option></select>
    <div class="row">
      <button class="gold" type="submit">ذخیره</button>
      <button class="outline" type="button" onclick="document.getElementById('user-dialog').close()">بستن</button>
    </div>
  </form>
</dialog>

<dialog id="ip-dialog">
  <h2>مدیریت مخزن IP</h2>
  <label>ثبت و فعال‌کردن یک IP</label>
  <input id="ip-input" placeholder="مثال: 104.16.132.229">
  <button class="gold" onclick="saveIp()">ثبت و فعال‌کردن</button>

  <label>واردکردن چند IP (هر خط یک IP)</label>
  <textarea id="bulk-ips" placeholder="104.16.132.229&#10;104.17.1.1"></textarea>
  <button class="gold" onclick="importIps()">واردکردن IPها</button>
  <button class="outline" onclick="getRanges()">دریافت محدوده‌های رسمی Cloudflare</button>

  <p class="muted">محدوده‌های رسمی، IPهای تست‌شده نیستند. نتیجه این پنل تضمین اتصال مستقیم VLESS نیست.</p>
  <div id="range-output"></div>
  <h3>IPهای ذخیره‌شده</h3>
  <div id="ip-list">در حال بارگذاری...</div>
  <button class="outline" onclick="document.getElementById('ip-dialog').close()">بستن</button>
</dialog>
</main>

<script>
const currentHost = ${safeHost};
let usersCache = [];
let ipsCache = [];

async function api(path, options={}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "خطای درخواست");
  return data;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[c]);
}

async function loadAll() {
  try {
    const data = await api("/api/users");
    usersCache = data.users || [];
    ipsCache = data.savedIps || [];
    document.getElementById("active-ip").textContent =
      "IP فعال: " + data.activeCleanIp;
    document.getElementById("total").textContent = data.metrics.total;
    document.getElementById("active").textContent = data.metrics.active;
    document.getElementById("ip-total").textContent = ipsCache.length;
    renderUsers();
    renderIps();
  } catch(e) {
    alert("خطا در دریافت اطلاعات: " + e.message);
  }
}

function renderUsers() {
  const root = document.getElementById("users");

  if (!usersCache.length) {
    root.innerHTML = '<div class="card">هنوز کاربری ثبت نشده است.</div>';
    return;
  }

  root.innerHTML = usersCache.map(u => {
    const sub = "/sub/" + encodeURIComponent(u.username);
    const yaml = "/yaml/" + encodeURIComponent(u.username);
    const status = u.status === "disabled" ? "غیرفعال" : "فعال";

    return '<article class="user">' +
      '<div class="row"><h2>' + esc(u.username) + '</h2><span>' + status + '</span></div>' +
      '<p class="muted">پروتکل: ' + esc(u.protocol) +
      ' | پورت: ' + esc(u.port) +
      ' | حجم: ' + esc(u.traffic) +
      ' | اعتبار: ' + esc(u.expire) + '</p>' +
      '<a class="button gold" href="' + sub + '" target="_blank">ساب متنی</a>' +
      '<a class="button outline" href="' + yaml + '" target="_blank">YAML</a>' +
      '<button class="outline" onclick="editUser(\\'' + esc(u.id) + '\\')">ویرایش</button>' +
      '<button class="danger" onclick="deleteUser(\\'' + esc(u.id) + '\\')">حذف</button>' +
      '</article>';
  }).join("");
}

function openUser() {
  document.getElementById("user-form").reset();
  document.getElementById("edit-id").value = "";
  document.getElementById("username").disabled = false;
  document.getElementById("user-title").textContent = "ایجاد کاربر";
  document.getElementById("user-dialog").showModal();
}

function editUser(id) {
  const u = usersCache.find(x => x.id === id);
  if (!u) return;

  document.getElementById("edit-id").value = u.id;
  document.getElementById("username").value = u.username;
  document.getElementById("username").disabled = true;
  document.getElementById("protocol").value = u.protocol || "VLESS";
  document.getElementById("port").value = u.port || "443";
  document.getElementById("traffic").value = parseInt(u.traffic) || 100;
  document.getElementById("expire").value = parseInt(u.expire) || 30;
  document.getElementById("status").value = u.status || "active";
  document.getElementById("user-title").textContent = "ویرایش کاربر";
  document.getElementById("user-dialog").showModal();
}

document.getElementById("user-form").addEventListener("submit", async e => {
  e.preventDefault();

  const id = document.getElementById("edit-id").value;
  const payload = {
    username: document.getElementById("username").value,
    protocol: document.getElementById("protocol").value,
    port: document.getElementById("port").value,
    traffic: document.getElementById("traffic").value,
    expire: document.getElementById("expire").value,
    status: document.getElementById("status").value
  };

  if (id) payload.id = id;

  try {
    const result = await api("/api/users", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });
    alert(result.message || "ذخیره شد");
    document.getElementById("user-dialog").close();
    loadAll();
  } catch(e) {
    alert(e.message);
  }
});

async function deleteUser(id) {
  if (!confirm("کاربر حذف شود؟")) return;

  try {
    await api("/api/users/" + encodeURIComponent(id), {method:"DELETE"});
    loadAll();
  } catch(e) {
    alert(e.message);
  }
}

function openIps() {
  document.getElementById("ip-dialog").showModal();
  renderIps();
}

function renderIps() {
  const root = document.getElementById("ip-list");

  if (!ipsCache.length) {
    root.innerHTML = '<p class="muted">مخزن خالی است.</p>';
    return;
  }

  root.innerHTML = ipsCache.map(item =>
    '<div class="ip row"><code>' + esc(item.ip) + '</code>' +
    '<div><button class="gold" onclick="selectIp(\\'' + esc(item.ip) + '\\')">انتخاب</button>' +
    '<button class="danger" onclick="deleteIp(\\'' + esc(item.id) + '\\')">حذف</button></div></div>'
  ).join("");
}

async function saveIp() {
  const ip = document.getElementById("ip-input").value.trim();
  if (!ip) return alert("IP را وارد کن.");

  try {
    await api("/api/set-clean-ip", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ip})
    });
    document.getElementById("ip-input").value = "";
    await loadAll();
    alert("IP ذخیره و فعال شد.");
  } catch(e) {
    alert(e.message);
  }
}

async function importIps() {
  const ips = document.getElementById("bulk-ips").value;

  try {
    const data = await api("/api/import-ips", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ips})
    });

    await loadAll();
    alert("ذخیره‌شده: " + data.saved);
  } catch(e) {
    alert(e.message);
  }
}

async function selectIp(ip) {
  try {
    await api("/api/select-clean-ip", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ip})
    });
    await loadAll();
    alert("IP فعال تغییر کرد.");
  } catch(e) {
    alert(e.message);
  }
}

async function deleteIp(id) {
  if (!confirm("این IP حذف شود؟")) return;

  try {
    await api("/api/delete-ip/" + encodeURIComponent(id), {
      method:"DELETE"
    });
    loadAll();
  } catch(e) {
    alert(e.message);
  }
}

async function getRanges() {
  const root = document.getElementById("range-output");
  root.textContent = "در حال دریافت...";

  try {
    const data = await api("/api/cloudflare-ranges");
    const ips = [...data.ipv4, ...data.ipv6];

    document.getElementById("bulk-ips").value = ips.join("\\n");
    root.textContent = "محدوده‌های رسمی دریافت شد: " +
      data.ipv4.length + " محدوده IPv4 و " +
      data.ipv6.length + " محدوده IPv6. برای ذخیره، دکمه واردکردن را بزن.";
  } catch(e) {
    root.textContent = e.message;
  }
}

loadAll();
</script>
</body>
</html>`;
}
