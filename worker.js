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
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT
        )`
      ).run();

      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS users (
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
        )`
      ).run();
    } catch (error) {
      return json({ success: false, error: "خطای آماده‌سازی دیتابیس." }, 500);
    }

    // -----------------------------------------------------
    // SECURE ADMIN AUTHENTICATION
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
        return new Response(
          `<!doctype html>
          <html lang="fa" dir="rtl">
          <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>ورود به KING PANEL</title>
          <style>
          :root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af}
          body{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}
          .login-card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:35px;width:100%;max-width:400px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
          h1{color:var(--gold);font-size:24px;margin-bottom:10px}
          p{color:var(--muted);font-size:14px;margin-bottom:25px}
          .badge{background:rgba(245,158,11,0.1);color:var(--gold);padding:6px 12px;border-radius:20px;font-size:12px;display:inline-block;margin-bottom:20px}
          </style>
          </head>
          <body>
          <div class="login-card">
          <span class="badge">👑 KING PANEL 👑</span>
          <h1>خوش آمدید مدیریت عزیز</h1>
          <p>لطفاً برای ورود به پنل، اطلاعات دسترسی خود را وارد کنید.</p>
          </div>
          </body>
          </html>`,
          {
            status: 401,
            headers: {
              "Content-Type": "text/html; charset=UTF-8",
              "WWW-Authenticate": 'Basic realm="KING PANEL"'
            }
          }
        );
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

    // دریافت تنظیمات از دیتابیس
    const [activeRow, echEnabledRow, echValueRow, fragEnabledRow, fragLenRow, fragIntRow] = await Promise.all([
      env.DB.prepare("SELECT value FROM settings WHERE key = 'clean_ip'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'ech_enabled'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'ech_value'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_enabled'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first().catch(() => null)
    ]);

    const publicUrl = env.PANEL_PUBLIC_URL || `https://${host}`;
    const connectionHost = env.CONNECTION_HOST || host;
    const activeCleanIp = activeRow?.value || connectionHost;
    const echEnabled = echEnabledRow?.value === "true";
    const echValue = echValueRow?.value || "cloudflare-ech.com+udp://1.1.1.1";

    const fragEnabled = fragEnabledRow?.value === "true";
    const fragLen = fragLenRow?.value || "100-200";
    const fragInt = fragIntRow?.value || "10-20";

    // -----------------------------------------------------
    // API: SAVE ECH SETTINGS
    // -----------------------------------------------------
    if (path === "/api/set-ech" && method === "POST") {
      const body = await readJson(request);
      if (!body) return json({ error: "اطلاعات ارسالی معتبر نیست." }, 400);

      const enabled = body.enabled ? "true" : "false";
      const value = String(body.value || "").trim();

      if (enabled === "true" && !value) {
        return json({ error: "مقدار ECH نمی‌تواند خالی باشد." }, 400);
      }

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('ech_enabled', ?)").bind(enabled).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('ech_value', ?)").bind(value).run();

      return json({ success: true, message: "تنظیمات ECH با موفقیت ذخیره شد." });
    }

    // -----------------------------------------------------
    // API: SAVE FRAGMENT SETTINGS
    // -----------------------------------------------------
    if (path === "/api/set-fragment" && method === "POST") {
      const body = await readJson(request);
      if (!body) return json({ error: "اطلاعات ارسالی معتبر نیست." }, 400);

      const enabled = body.enabled ? "true" : "false";
      const length = String(body.length || "100-200").trim();
      const interval = String(body.interval || "10-20").trim();

      const rangeRegex = /^(\d+)(-\d+)?$/;
      if (!rangeRegex.test(length) || !rangeRegex.test(interval)) {
        return json({ error: "فرمت طول یا بازه فرگمنت نامعتبر است." }, 400);
      }

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_enabled', ?)").bind(enabled).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_len', ?)").bind(length).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_int', ?)").bind(interval).run();

      return json({ success: true, message: "تنظیمات فرگمنت با موفقیت ذخیره شد." });
    }

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

      // ساخت پارامترهای پیشرفته جهت سازگاری حداکثری با کلاینت‌های قدرتمند
      const fragmentParam = fragEnabled ? `&packet=tls&length=${encodeURIComponent(fragLen)}&interval=${encodeURIComponent(fragInt)}` : "";
      const echParam = (echEnabled && protocol !== "shadowsocks" && protocol !== "ss")
        ? `&ech=${encodeURIComponent(echValue)}`
        : "";

      if (protocol === "vless") {
        config = `vless://${user.uuid}@${activeCleanIp}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(connectionHost)}&fp=chrome&type=ws&host=${encodeURIComponent(connectionHost)}&path=\%2F\%3Fed\%3D2048${fragmentParam}${echParam}#${name}`;
      } else if (protocol === "trojan") {
        config = `trojan://${user.uuid}@${activeCleanIp}:${port}?security=tls&sni=${encodeURIComponent(connectionHost)}&type=ws&host=${encodeURIComponent(connectionHost)}&path=\%2F\%3Fed\%3D2048${fragmentParam}${echParam}#${name}`;
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
          `    servername: "${yamlEscape(connectionHost)}"`,
          "    skip-cert-verify: false",
          (echEnabled && protocol !== "shadowsocks") ? `    ech-config: "${yamlEscape(echValue)}"` : "",
          "    ws-opts:",
          '      path: "/?ed=2048"',
          "      headers:",
          `        Host: "${yamlEscape(connectionHost)}"`,
          "    client-fingerprint: chrome",
          fragEnabled ? "    fragment: tls" : "",
          fragEnabled ? `    fragment-length: ${yamlEscape(fragLen)}` : "",
          fragEnabled ? `    fragment-interval: ${yamlEscape(fragInt)}` : ""
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
    // USER STATUS PAGE
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

      return html(
        `<!doctype html>
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
        </html>`
      );
    }

    // -----------------------------------------------------
    // GET USERS, SAVED IPS & SETTINGS
    // -----------------------------------------------------
    if (path === "/api/users" && method === "GET") {
      const usersResult = await env.DB.prepare("SELECT * FROM users ORDER BY rowid DESC").all();
      const ipsResult = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'ip_%'").all();

      return json({
        success: true,
        users: usersResult.results || [],
        savedIps: (ipsResult.results || []).map(row => ({ id: row.key, ip: row.value })),
        activeCleanIp,
        publicUrl,
        connectionHost,
        echSettings: {
          enabled: echEnabled,
          value: echValue
        },
        fragmentSettings: {
          enabled: fragEnabled,
          length: fragLen,
          interval: fragInt
        },
        metrics: {
          total: (usersResult.results || []).length,
          active: (usersResult.results || []).filter(u => u.status === 'active').length,
          disabled: (usersResult.results || []).filter(u => u.status === 'disabled').length
        }
      });
    }

    // -----------------------------------------------------
    // ADD OR EDIT USER
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
        return json({ error: "پورت معتبر نیست." }, 400);
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

        await env.DB.prepare(
          `UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, status = ? WHERE id = ?`
        ).bind(protocol, traffic, expire, port, status, String(body.id)).run();

        return json({ success: true, message: "کاربر با موفقیت ویرایش شد." });
      }

      const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
      if (existing) return json({ error: "این نام کاربری قبلاً ثبت شده است." }, 409);

      const id = "usr_" + crypto.randomUUID();
      const uuid = crypto.randomUUID();

      await env.DB.prepare(
        `INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?)`
      ).bind(id, username, uuid, protocol, traffic, expire, port, status).run();

      return json({ success: true, message: "کاربر جدید ثبت شد." });
    }

    // -----------------------------------------------------
    // REGENERATE UUID
    // -----------------------------------------------------
    if (path.startsWith("/api/users/regen/") && method === "POST") {
      const id = decodeURIComponent(path.slice("/api/users/regen/".length));
      if (!id) return json({ error: "شناسه نامعتبر است." }, 400);

      const newUuid = crypto.randomUUID();
      await env.DB.prepare("UPDATE users SET uuid = ? WHERE id = ?").bind(newUuid, id).run();
      return json({ success: true, message: "UUID کاربر با موفقیت بازسازی شد.", uuid: newUuid });
    }

    // -----------------------------------------------------
    // TOGGLE USER STATUS
    // -----------------------------------------------------
    if (path.startsWith("/api/users/status/") && method === "POST") {
      const id = decodeURIComponent(path.slice("/api/users/status/".length));
      const body = await readJson(request);
      const newStatus = body?.status === "disabled" ? "disabled" : "active";

      await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(newStatus, id).run();
      return json({ success: true, message: "وضعیت کاربر به‌روز شد." });
    }

    // -----------------------------------------------------
    // DELETE USER
    // -----------------------------------------------------
    if (path.startsWith("/api/users/") && method === "DELETE") {
      const id = decodeURIComponent(path.slice("/api/users/".length));
      if (!id) return json({ error: "شناسه نامعتبر است." }, 400);

      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
      return json({ success: true, message: "کاربر حذف شد." });
    }

    // -----------------------------------------------------
    // SET CLEAN IP
    // -----------------------------------------------------
    if (path === "/api/set-clean-ip" && method === "POST") {
      const body = await readJson(request);
      const ip = String(body?.ip || "").trim();
      if (!isValidIp(ip)) return json({ error: "قالب IP معتبر نیست." }, 400);

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

    return html(dashboard(host, publicUrl));
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

function dashboard(host, publicUrl) {
  const safeHost = JSON.stringify(host);
  const safePublicUrl = JSON.stringify(publicUrl);
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KING PANEL</title>
<style>
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af;--green:#10b981;--red:#ef4444;--purple:#8b5cf6;--teal:#14b8a6}
*{box-sizing:border-box}
body{margin:0;padding:15px;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif}
main{max-width:1100px;margin:auto}
header,.card,.toolbar,.box{background:var(--card);border:1px solid var(--border);border-radius:15px;padding:17px;margin-bottom:15px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:21px;color:var(--gold);margin:0}
h2{font-size:16px}
.muted{color:var(--muted);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:15px}
.stat{background:var(--card);border:1px solid var(--border);padding:16px;border-radius:12px}
.stat b{display:block;font-size:22px;color:var(--gold);margin-top:6px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap}
input,select,textarea{width:100%;padding:11px;background:var(--bg);color:white;border:1px solid var(--border);border-radius:9px;margin:5px 0 12px}
textarea{min-height:110px}
button,.button{border:0;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block;margin:3px;font-size:13px}
.gold{background:var(--gold);color:#111}
.teal{background:var(--teal);color:#111}
.outline{background:#111827;color:white;border:1px solid var(--border)}
.danger{background:#451a1a;color:#fecaca}
.user{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:15px;margin:12px 0;overflow-wrap:anywhere}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.tag{font-size:12px;color:var(--green)}
.ip{padding:10px;border-bottom:1px solid var(--border);overflow-wrap:anywhere}
dialog{width:min(650px,95vw);max-height:90vh;overflow:auto;background:var(--card);color:white;border:1px solid var(--gold);border-radius:15px}
dialog::backdrop{background:#000b}
.config-card { background: #07111e; border: 1px solid #132238; border-radius: 14px; padding: 15px; margin-bottom: 15px; }
.config-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
.switch { position: relative; display: inline-block; width: 46px; height: 24px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #1e2634; transition: .3s; border-radius: 24px; }
.slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
input:checked + .slider { background-color: var(--teal); }
input:checked + .slider:before { transform: translateX(22px); }
.config-body { margin-top: 15px; display: none; border-top: 1px solid var(--border); padding-top: 15px; }
.config-body.show { display: block; }
.warning-box { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); padding: 10px; border-radius: 8px; font-size: 12px; color: #fca5a5; display: flex; gap: 8px; align-items: center; margin-top: 10px; }
.preset-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-top: 10px; }
.preset-btn { background: #0d1522; border: 1px solid var(--border); color: var(--text); padding: 8px; border-radius: 8px; cursor: pointer; font-size: 11px; text-align: center; }
.preset-btn:hover { border-color: var(--teal); }
</style>
</head>
<body>
<main>
<header>
  <h1>👑 KING PANEL</h1>
  <div class="tag" id="active-ip">در حال دریافت IP فعال...</div>
</header>
<section class="stats">
  <div class="stat">کل کاربران<b id="total">0</b></div>
  <div class="stat">کاربران فعال<b id="active">0</b></div>
  <div class="stat">غیرفعال<b id="disabled">0</b></div>
  <div class="stat">IPهای مخزن<b id="ip-total">0</b></div>
</section>
<div class="toolbar" style="background:var(--card);border:1px solid var(--border);border-radius:15px;padding:15px;margin-bottom:15px;">
  <input id="search-input" placeholder="🔍 جستجوی نام کاربری..." oninput="filterUsers()" style="margin:0;flex:2;min-width:200px;">
  <select id="filter-status" onchange="filterUsers()" style="margin:0;flex:1;min-width:140px;">
    <option value="all">همه کاربران</option>
    <option value="active">فقط فعال‌ها</option>
    <option value="disabled">فقط غیرفعال‌ها</option>
  </select>
</div>
<section class="config-card">
  <div class="config-header" onclick="toggleBody('ech-body-content')">
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="color:var(--purple);font-size:18px;">🔒</span>
      <div>
        <h2 style="margin:0;color:var(--text);">تنظیمات ECH (Encrypted Client Hello)</h2>
        <div class="muted">رمزنگاری نام سرور در دسترسی TLS</div>
      </div>
    </div>
    <label class="switch" onclick="event.stopPropagation()">
      <input type="checkbox" id="ech-toggle" onchange="saveEchSettings(true)">
      <span class="slider"></span>
    </label>
  </div>
  <div class="config-body" id="ech-body-content">
    <label>مقدار ECH</label>
    <input id="ech-value-input" placeholder="cloudflare-ech.com+udp://1.1.1.1" value="cloudflare-ech.com+udp://1.1.1.1">
    <div class="row" style="margin-top:15px;">
      <button class="gold" onclick="saveEchSettings()">ذخیره ECH</button>
      <button class="outline" onclick="toggleBody('ech-body-content')">بستن</button>
    </div>
  </div>
</section>
<section class="config-card">
  <div class="config-header" onclick="toggleBody('frag-body-content')">
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="color:var(--teal);font-size:18px;">⚡</span>
      <div>
        <h2 style="margin:0;color:var(--text);">تنظیمات فرگمنت ضد فیلترینگ (Fragment)</h2>
        <div class="muted">تکه‌تکه کردن پکت‌های اتصال برای عبور از فیلترینگ</div>
      </div>
    </div>
    <label class="switch" onclick="event.stopPropagation()">
      <input type="checkbox" id="frag-toggle" onchange="saveFragmentSettings(true)">
      <span class="slider"></span>
    </label>
  </div>
  <div class="config-body" id="frag-body-content">
    <label>طول فرگمنت (Length)</label>
    <input id="frag-len-input" placeholder="100-200" value="100-200">
    <label>بازه فرگمنت (Interval ms)</label>
    <input id="frag-int-input" placeholder="10-20" value="10-20">
    <div class="warning-box">
      ⚠️ برای حداکثر پایداری، مطمئن شوید که از یک IP تمیز سالم استفاده می‌کنید.
    </div>
    <label style="margin-top:10px;display:block;">پیشنهاد اپراتورها:</label>
    <div class="preset-grid">
      <div class="preset-btn" onclick="setPreset('10-30', '2-5')">🟢 همراه اول</div>
      <div class="preset-btn" onclick="setPreset('100-200', '5-10')">🟡 ایرانسل</div>
      <div class="preset-btn" onclick="setPreset('50-100', '2-5')">🟣 رایتل</div>
    </div>
    <div class="row" style="margin-top:15px;">
      <button class="teal" onclick="saveFragmentSettings()">ذخیره فرگمنت</button>
      <button class="outline" onclick="toggleBody('frag-body-content')">بستن</button>
    </div>
  </div>
</section>
<div class="toolbar">
  <button class="gold" onclick="openUser()">+ ایجاد کاربر</button>
  <button class="outline" onclick="openIps()">مدیریت IPها</button>
  <button class="outline" onclick="openDiagnostics()">🔍 عیب‌یابی و وضعیت</button>
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
    <div class="row" style="margin-top:15px;">
      <button class="gold" type="submit">ذخیره کاربر</button>
      <button class="outline" type="button" onclick="document.getElementById('user-dialog').close()">انصراف</button>
    </div>
  </form>
</dialog>
<dialog id="ip-dialog">
  <h2>مدیریت مخزن IP</h2>
  <label>ثبت و فعال‌کردن یک IP</label>
  <input id="ip-input" placeholder="مثال: 104.16.132.229">
  <button class="gold" onclick="saveIp()">ثبت و فعال‌کردن</button>
  <label>واردکردن گروهی IP (هر خط یک IP)</label>
  <textarea id="bulk-ips" placeholder="104.16.132.229&#10;104.17.1.1"></textarea>
  <button class="gold" onclick="importIps()">واردکردن IPها</button>
  <button class="outline" onclick="getRanges()">دریافت محدوده‌های رسمی Cloudflare</button>
  <div id="range-output" class="muted" style="margin-top:8px;"></div>
  <h3>IPهای ذخیره‌شده</h3>
  <div id="ip-list">در حال بارگذاری...</div>
  <button class="outline" style="margin-top:15px;" onclick="document.getElementById('ip-dialog').close()">بستن</button>
</dialog>
<dialog id="diag-dialog">
  <h2>گزارش عیب‌یابی سیستم</h2>
  <div id="diag-content" style="font-size:13px;line-height:1.8;background:#030508;padding:12px;border-radius:10px;border:1px solid var(--border);">در حال بررسی...</div>
  <button class="outline" style="margin-top:15px;" onclick="document.getElementById('diag-dialog').close()">بستن</button>
</dialog>
</main>
<script>
const currentHost = ${safeHost};
const publicPanelUrl = ${safePublicUrl};
let usersCache = [];
let ipsCache = [];
let systemInfo = {};

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

function toggleBody(id) {
  document.getElementById(id).classList.toggle("show");
}

function setPreset(len, intVal) {
  document.getElementById("frag-len-input").value = len;
  document.getElementById("frag-int-input").value = intVal;
  alert("مقادیر پیشنهادی اپراتور اعمال شد. روی ذخیره فرگمنت کلیک کنید.");
}

async function saveEchSettings(isToggleOnly = false) {
  const enabled = document.getElementById("ech-toggle").checked;
  const value = document.getElementById("ech-value-input").value.trim();
  try {
    const res = await api("/api/set-ech", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ enabled, value })
    });
    if (!isToggleOnly) alert(res.message || "ذخیره شد.");
  } catch(e) {
    alert("خطا: " + e.message);
  }
}

async function saveFragmentSettings(isToggleOnly = false) {
  const enabled = document.getElementById("frag-toggle").checked;
  const length = document.getElementById("frag-len-input").value.trim();
  const interval = document.getElementById("frag-int-input").value.trim();
  try {
    const res = await api("/api/set-fragment", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ enabled, length, interval })
    });
    if (!isToggleOnly) alert(res.message || "ذخیره شد.");
  } catch(e) {
    alert("خطا: " + e.message);
    document.getElementById("frag-toggle").checked = !enabled;
  }
}

async function loadAll() {
  try {
    const data = await api("/api/users");
    usersCache = data.users || [];
    ipsCache = data.savedIps || [];
    systemInfo = data;

    document.getElementById("active-ip").textContent = "IP فعال: " + data.activeCleanIp;
    document.getElementById("total").textContent = data.metrics.total;
    document.getElementById("active").textContent = data.metrics.active;
    document.getElementById("disabled").textContent = data.metrics.disabled;
    document.getElementById("ip-total").textContent = ipsCache.length;

    if (data.echSettings) {
      document.getElementById("ech-toggle").checked = data.echSettings.enabled;
      document.getElementById("ech-value-input").value = data.echSettings.value;
    }
    if (data.fragmentSettings) {
      document.getElementById("frag-toggle").checked = data.fragmentSettings.enabled;
      document.getElementById("frag-len-input").value = data.fragmentSettings.length;
      document.getElementById("frag-int-input").value = data.fragmentSettings.interval;
    }

    filterUsers();
    renderIps();
  } catch(e) {
    alert("خطا در دریافت اطلاعات: " + e.message);
  }
}

function filterUsers() {
  const search = document.getElementById("search-input").value.toLowerCase();
  const statusFilter = document.getElementById("filter-status").value;

  const filtered = usersCache.filter(u => {
    const matchName = u.username.toLowerCase().includes(search);
    const matchStatus = statusFilter === "all" || u.status === statusFilter;
    return matchName && matchStatus;
  });

  renderUsersList(filtered);
}

function renderUsersList(list) {
  const root = document.getElementById("users");
  if (!list.length) {
    root.innerHTML = '<div class="card">کاربری یافت نشد.</div>';
    return;
  }

  root.innerHTML = list.map(u => {
    const subUrl = publicPanelUrl + "/sub/" + encodeURIComponent(u.username);
    const yamlUrl = publicPanelUrl + "/yaml/" + encodeURIComponent(u.username);
    const statusText = u.status === "disabled" ? "غیرفعال" : "فعال";
    const statusColor = u.status === "disabled" ? "var(--red)" : "var(--green)";

    return '<article class="user">' +
      '<div class="row"><h2>' + esc(u.username) + '</h2><span style="color:' + statusColor + '">' + statusText + '</span></div>' +
      '<p class="muted">پروتکل: ' + esc(u.protocol) + ' | پورت: ' + esc(u.port) + ' | حجم: ' + esc(u.traffic) + ' | اعتبار: ' + esc(u.expire) + '</p>' +
      '<div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap">' +
        '<button class="gold" onclick="copyText(\\'' + subUrl + '\\', \\'لینک ساب‌سکرپشن کپی شد!\\')">📋 کپی ساب</button>' +
        '<button class="outline" onclick="copyText(\\'' + yamlUrl + '\\', \\'لینک YAML کپی شد!\\')">📄 کپی YAML</button>' +
        '<button class="outline" onclick="copyText(\\'' + esc(u.uuid) + '\\', \\'UUID کپی شد!\\')">🔑 کپی UUID</button>' +
        '<button class="outline" onclick="toggleUserStatus(\\'' + esc(u.id) + '\\', \\'' + esc(u.status) + '\\')">' + (u.status === 'disabled' ? '✅ فعال‌سازی' : '⛔ غیرفعال‌سازی') + '</button>' +
        '<button class="outline" onclick="regenUuid(\\'' + esc(u.id) + '\\')">🔄 بازسازی UUID</button>' +
        '<button class="outline" onclick="editUser(\\'' + esc(u.id) + '\\')">✏️ ویرایش</button>' +
        '<button class="danger" onclick="deleteUser(\\'' + esc
