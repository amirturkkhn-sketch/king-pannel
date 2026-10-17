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
          status TEXT,
          created_at TEXT
        )
      `).run();
    } catch (error) {
      return json({ success: false, error: "خطای آماده‌سازی دیتابیس." }, 500);
    }

    // احراز هویت ادمین با صفحه ورود شیک و مدرن برند KING PANEL
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
        return new Response(`
          <!doctype html>
          <html lang="fa" dir="rtl">
          <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>ورود به پنل مدیریت KING PANEL</title>
          <style>
            :root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af;--blue:#3b82f6;}
            body{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}
            .login-card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:35px;width:100%;max-width:400px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
            h1{color:var(--gold);font-size:22px;margin-bottom:10px}
            p{color:var(--muted);font-size:14px;margin-bottom:25px}
            .badge{background:rgba(59,130,246,0.1);color:var(--blue);padding:6px 14px;border-radius:20px;font-size:12px;display:inline-block;margin-bottom:20px;font-weight:bold}
          </style>
          </head>
          <body>
            <div class="login-card">
              <span class="badge">👑 KING PANEL MANAGEMENT 👑</span>
              <h1>خوش آمدید مدیریت عزیز</h1>
              <p>لطفاً برای دسترسی به پنل، احراز هویت نمایید.</p>
            </div>
          </body>
          </html>
        `, {
          status: 401,
          headers: {
            "Content-Type": "text/html; charset=UTF-8",
            "WWW-Authenticate": 'Basic realm="KING PANEL"'
          }
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

    // بازیابی تنظیمات از دیتابیس
    const [activeRow, echEnabledRow, echValueRow, fragEnabledRow, fragLenRow, fragIntRow] = await Promise.all([
      env.DB.prepare("SELECT value FROM settings WHERE key = 'clean_ip'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'ech_enabled'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'ech_value'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_enabled'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first().catch(() => null),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first().catch(() => null)
    ]);

    const activeCleanIp = activeRow?.value || host;
    const echEnabled = echEnabledRow?.value === "true";
    const echValue = echValueRow?.value || "cloudflare-ech.com+udp://1.1.1.1";
    const fragEnabled = fragEnabledRow?.value !== "false";
    const fragLen = fragLenRow?.value || "100-200";
    const fragInt = fragIntRow?.value || "10-20";

    // API: ذخیره تنظیمات ECH
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

    // API: ذخیره تنظیمات Fragment
    if (path === "/api/set-fragment" && method === "POST") {
      const body = await readJson(request);
      if (!body) return json({ error: "اطلاعات ارسالی معتبر نیست." }, 400);

      const enabled = body.enabled ? "true" : "false";
      const length = String(body.length || "100-200").trim();
      const interval = String(body.interval || "10-20").trim();

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_enabled', ?)").bind(enabled).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_len', ?)").bind(length).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_int', ?)").bind(interval).run();

      return json({ success: true, message: "تنظیمات فرگمنت با موفقیت ذخیره شد." });
    }

    // تولید ساب‌سکرپشن و فایل YAML
    if ((path.startsWith("/sub/") || path.startsWith("/yaml/")) && method === "GET") {
      const username = decodeURIComponent(path.split("/")[2] || "");
      if (!username) return new Response("Username required", { status: 400 });

      const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      if (!user) return new Response("User not found", { status: 404 });
      if (user.status === "disabled") return new Response("Subscription disabled", { status: 403 });

      const port = Number(user.port || 443);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return new Response("Invalid port", { status: 500 });
      }

      const protocol = (user.protocol || "VLESS").toLowerCase();
      const name = encodeURIComponent(user.username);
      let config = "";

      const fragmentParam = fragEnabled ? `&packet=tls&length=${fragLen}&interval=${fragInt}` : "";
      const echParam = (echEnabled && protocol !== "shadowsocks" && protocol !== "ss") 
        ? `&ech=${encodeURIComponent(echValue)}` 
        : "";

      if (protocol === "vless") {
        config = `vless://${user.uuid}@${activeCleanIp}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(host)}&fp=chrome&type=ws&host=${encodeURIComponent(host)}&path=%2F%3Fed%3D2048${fragmentParam}${echParam}#${name}`;
      } else if (protocol === "trojan") {
        config = `trojan://${user.uuid}@${activeCleanIp}:${port}?security=tls&sni=${encodeURIComponent(host)}&type=ws&host=${encodeURIComponent(host)}&path=%2F%3Fed%3D2048${fragmentParam}${echParam}#${name}`;
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
          (echEnabled && protocol !== "shadowsocks") ? `    ech-config: "${yamlEscape(echValue)}"` : "",
          "    ws-opts:",
          '      path: "/?ed=2048"',
          "      headers:",
          `        Host: "${yamlEscape(host)}"`,
          "    client-fingerprint: chrome",
          fragEnabled ? `    fragment: tls` : "",
          fragEnabled ? `    fragment-length: ${fragLen}` : "",
          fragEnabled ? `    fragment-interval: ${fragInt}` : ""
        ].filter(Boolean).join("\n");

        return new Response(yaml, {
          headers: { "Content-Type": "text/yaml; charset=UTF-8", "Cache-Control": "no-store" }
        });
      }

      return new Response(btoa(unescape(encodeURIComponent(config))), {
        headers: { "Content-Type": "text/plain; charset=UTF-8", "Cache-Control": "no-store" }
      });
    }

    // صفحه وضعیت کاربر
    if (path.startsWith("/status/") && method === "GET") {
      const username = decodeURIComponent(path.split("/")[2] || "");
      const user = await env.DB.prepare("SELECT username, status FROM users WHERE username = ?").bind(username).first();
      if (!user) return new Response("کاربر پیدا نشد.", { status: 404 });

      return html(`
        <!doctype html>
        <html lang="fa" dir="rtl">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>وضعیت اشتراک - کینگ پنل</title>
        <body style="background:#030508;color:#fff;font-family:sans-serif;padding:30px">
          <main style="max-width:480px;margin:auto;background:#0a0e17;padding:25px;border-radius:18px;border:1px solid #1e2634">
            <h2 style="color:#f59e0b">${escapeHtml(user.username)}</h2>
            <p>وضعیت حساب: ${user.status === "disabled" ? "غیرفعال" : "فعال"}</p>
          </main>
        </body>
        </html>
      `);
    }

    // API دریافت لیست کاربران و آمار سرور
    if (path === "/api/users" && method === "GET") {
      const usersResult = await env.DB.prepare("SELECT * FROM users ORDER BY rowid DESC").all();
      const ipsResult = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'ip_%'").all();
      const users = usersResult.results || [];
      
      const total = users.length;
      const active = users.filter(u => u.status === 'active').length;
      const disabled = users.filter(u => u.status === 'disabled').length;

      return json({
        success: true,
        users,
        savedIps: (ipsResult.results || []).map(row => ({ id: row.key, ip: row.value })),
        activeCleanIp,
        echSettings: { enabled: echEnabled, value: echValue },
        fragmentSettings: { enabled: fragEnabled, length: fragLen, interval: fragInt },
        metrics: { total, active, expired: disabled }
      });
    }

    // API ایجاد یا ویرایش کاربر
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
      const now = new Date().toISOString();

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
        INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?, ?)
      `).bind(id, username, uuid, protocol, traffic, expire, port, status, now).run();

      return json({ success: true, message: "کاربر ثبت شد." });
    }

    // API حذف کاربر
    if (path.startsWith("/api/users/") && method === "DELETE") {
      const id = decodeURIComponent(path.slice("/api/users/".length));
      if (!id) return json({ error: "شناسه نامعتبر است." }, 400);

      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
      return json({ success: true });
    }

    // مدیریت IP های تمیز
    if (path === "/api/set-clean-ip" && method === "POST") {
      const body = await readJson(request);
      const ip = String(body?.ip || "").trim();
      if (!isValidIp(ip)) return json({ error: "قالب IP معتبر نیست." }, 400);

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(makeIpKey(ip), ip).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();

      return json({ success: true, activeCleanIp: ip });
    }

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
<title>KING PANEL - Zeus Edition</title>
<style>
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af;--green:#10b981;--red:#ef4444;--purple:#8b5cf6;--blue:#3b82f6;--teal:#14b8a6}
*{box-sizing:border-box}
body{margin:0;padding:15px;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;-webkit-tap-highlight-color:transparent;}
main{max-width:1150px;margin:auto}
header,.card,.toolbar,.zeus-box{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:16px;box-shadow:0 4px 20px rgba(0,0,0,0.3)}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:22px;color:var(--gold);margin:0;display:flex;align-items:center;gap:8px}
h2{font-size:16px;margin:0 0 10px 0}
.muted{color:var(--muted);font-size:12px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--border);padding:18px;border-radius:14px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;background:var(--blue)}
.stat:nth-child(2)::after{background:var(--teal)}
.stat:nth-child(3)::after{background:var(--purple)}
.stat b{display:block;font-size:20px;color:var(--text);margin-top:6px}

.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select,textarea{width:100%;padding:12px 14px;background:var(--bg);color:white;border:1px solid var(--border);border-radius:10px;margin:6px 0 14px;font-size:14px;transition:border-color 0.2s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--blue)}
textarea{min-height:100px;font-family:monospace}

button,.button{border:0;border-radius:10px;padding:11px 16px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;margin:3px;font-size:13px;transition:opacity 0.2s,transform 0.1s}
button:active{transform:scale(0.98)}
.blue{background:var(--blue);color:white}
.gold{background:var(--gold);color:#111}
.teal{background:var(--teal);color:#111}
.outline{background:#111827;color:white;border:1px solid var(--border)}
.danger{background:#451a1a;color:#fecaca}
.success{background:#064e3b;color:#a7f3d0}

.user-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;margin:14px 0;transition:border-color 0.2s}
.user-card:hover{border-color:var(--blue)}
.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.tag{font-size:12px;color:var(--teal);background:rgba(20,184,166,0.1);padding:4px 10px;border-radius:20px;border:1px solid rgba(20,184,166,0.2)}
.ip-item{padding:12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:10px}

dialog{width:min(720px,96vw);max-height:92vh;background:var(--card);color:white;border:1px solid var(--border);border-radius:20px;padding:0;box-shadow:0 25px 50px rgba(0,0,0,0.7)}
dialog::backdrop{background:rgba(0,0,0,0.8);backdrop-filter:blur(4px)}
.modal-header{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.modal-body{padding:20px 24px;overflow-y:auto;max-height:calc(92vh - 140px)}
.modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px;background:#05080f}

.tabs{display:flex;gap:6px;border-bottom:1px solid var(--border);margin-bottom:18px;overflow-x:auto;padding-bottom:4px}
.tab-btn{background:transparent;color:var(--muted);border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-weight:600;white-space:nowrap}
.tab-btn.active{background:var(--blue);color:white}
.tab-pane{display:none}
.tab-pane.active{display:block}

.config-section{background:#07111e;border:1px solid #132238;border-radius:14px;padding:18px;margin-bottom:16px}
.config-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer}
.switch{position:relative;display:inline-block;width:48px;height:26px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#1e2634;transition:.3s;border-radius:26px}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background-color:white;transition:.3s;border-radius:50%}
input:checked+.slider{background-color:var(--teal)}
input:checked+.slider:before{transform:translateX(22px)}
.config-body{margin-top:16px;display:none;border-top:1px solid var(--border);padding-top:16px}
.config-body.show{display:block}
.warning-alert{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:12px;border-radius:10px;font-size:12px;color:#fca5a5;display:flex;gap:10px;align-items:center;margin-top:12px}

/* دکمه‌های پیش‌فرض اپراتورها در مودال */
.preset-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-top:10px}
.preset-btn{background:#0d1522;border:1px solid var(--border);color:var(--text);padding:10px;border-radius:8px;cursor:pointer;font-size:12px;text-align:center}
.preset-btn:hover{border-color:var(--teal)}

@media(max-width:640px){
  body{padding:10px}
  header,.card,.toolbar{padding:14px}
  .toolbar{flex-direction:column;align-items:stretch}
  button,.button{width:100%;margin:4px 0}
  .modal-footer{position:sticky;bottom:0;z-index:10}
}
</style>
</head>
<body>
<main>
<header>
  <h1>👑 KING PANEL (Zeus Edition)</h1>
  <div class="tag" id="active-ip">در حال دریافت IP فعال...</div>
</header>

<!-- کارت‌های آمار و وضعیت سرور مشابه مرجع ZEUS -->
<section class="stats">
  <div class="stat">کل کاربران ثبت‌شده<b id="total">0</b></div>
  <div class="stat">کاربران فعال<b id="active">0</b></div>
  <div class="stat">غیرفعال / منقضی<b id="expired">0</b></div>
  <div class="stat">IPهای مخزن<b id="ip-total">0</b></div>
</section>

<!-- بخش تنظیمات پیشرفته ECH -->
<section class="config-section">
  <div class="config-header" onclick="toggleConfigBody('ech-body')">
    <div style="display:flex;align-items:center;gap:12px;">
      <span style="color:var(--purple);font-size:20px;">🔒</span>
      <div>
        <h2>تنظیمات پیشرفته ECH (Encrypted Client Hello)</h2>
        <div class="muted">رمزنگاری SNI برای دورزدن مسدودسازی‌های لایه انتقال TLS</div>
      </div>
    </div>
    <label class="switch" onclick="event.stopPropagation()">
      <input type="checkbox" id="ech-toggle" onchange="saveEchSettings(true)">
      <span class="slider"></span>
    </label>
  </div>
  <div class="config-body" id="ech-body">
    <label>مقدار ECH Config</label>
    <input id="ech-value-input" placeholder="cloudflare-ech.com+udp://1.1.1.1">
    <div class="warning-alert">
      <span>⚠️ توجه: ECH تنها روی پروتکل‌ها و کلاینت‌های سازگار عمل می‌کند.</span>
    </div>
    <div class="row" style="margin-top:15px;">
      <button class="teal" onclick="saveEchSettings()">ذخیره تغییرات ECH</button>
      <button class="outline" onclick="toggleConfigBody('ech-body')">بستن</button>
    </div>
  </div>
</section>

<!-- بخش تنظیمات پیشرفته Fragment (منطبق با تصاویر مرجع) -->
<section class="config-section">
  <div class="config-header" onclick="toggleConfigBody('frag-body')">
    <div style="display:flex;align-items:center;gap:12px;">
      <span style="color:var(--teal);font-size:20px;">⚡</span>
      <div>
        <h2>فرگمنت ضد فیلترینگ (Fragment)</h2>
        <div class="muted">تکه‌تکه کردن پکت‌های اتصال برای عبور تضمینی (تست‌شده و موفق)</div>
      </div>
    </div>
    <label class="switch" onclick="event.stopPropagation()">
      <input type="checkbox" id="frag-toggle" onchange="saveFragmentSettings(true)">
      <span class="slider"></span>
    </label>
  </div>
  <div class="config-body" id="frag-body">
    <label>طول فرگمنت (Length) - بایت‌های تقسیم پکت</label>
    <input id="frag-len-input" placeholder="100-200" value="100-200">
    <label>بازه فرگمنت (Interval ms) - تاخیر میلی‌ثانیه</label>
    <input id="frag-int-input" placeholder="10-20" value="10-20">
    
    <label style="margin-top:12px;display:block;">تنظیمات پیشنهادی برای اپراتورها (کلیک برای اعمال خودکار):</label>
    <div class="preset-grid">
      <div class="preset-btn" onclick="setPreset('10-30', '2-5')">🟢 همراه اول (MCI)<br><small>شکستن پکت</small></div>
      <div class="preset-btn" onclick="setPreset('100-200', '5-10')">🟡 ایرانسل (MTN)<br><small>پایداری 4G/5G</small></div>
      <div class="preset-btn" onclick="setPreset('50-100', '2-5')">🟣 رایتل (Rightel)<br><small>بهینه 3G/4G</small></div>
    </div>

    <div class="warning-alert" style="margin-top:15px;">
      <span>ℹ️ این تنظیم روی کانفیگ‌های خروجی ساب‌سکرپشن و YAML به صورت استاندارد اعمال می‌شود.</span>
    </div>
    <div class="row" style="margin-top:15px;">
      <button class="teal" onclick="saveFragmentSettings()">ذخیره تنظیمات فرگمنت</button>
      <button class="outline" onclick="toggleConfigBody('frag-body')">بستن</button>
    </div>
  </div>
</section>

<div class="toolbar">
  <button class="blue" onclick="openUserModal()">+ ایجاد کاربر جدید</button>
  <button class="outline" onclick="openIpsModal()">مدیریت مخزن IP و پورت</button>
  <button class="outline" onclick="loadAll()">بروزرسانی داده‌ها</button>
</div>

<section id="users-list"></section>

<!-- مودال پیشرفته ۴ تب (مشابه تصاویر مرجع ZEUS) -->
<dialog id="user-modal">
  <div class="modal-header">
    <h2 id="modal-title" style="margin:0;color:var(--gold);">ایجاد کاربر جدید</h2>
    <button class="outline" style="padding:6px 10px;margin:0;" onclick="closeUserModal()">✕</button>
  </div>
  
  <div class="modal-body">
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab(event, 'tab-spec')">۱. مشخصات</button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-network')">۲. پورت و IP</button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-proxy')">۳. پروکسی</button>
      <button class="tab-btn" onclick="switchTab(event, 'tab-advanced')">۴. پیشرفته</button>
    </div>

    <form id="user-form">
      <input id="edit-id" type="hidden">
      
      <!-- تب ۱: مشخصات -->
      <div id="tab-spec" class="tab-pane active">
        <label>نام کاربری (الزامی)</label>
        <div class="row" style="gap:0;">
          <input id="username" required placeholder="مثلاً ali" style="margin-bottom:6px;">
        </div>
        <div class="muted">نام کاربری به صورت خودکار با پیشوند استاندارد کینگ پنل ثبت می‌شود.</div>
        
        <label style="margin-top:14px;display:block;">وضعیت حساب</label>
        <select id="status">
          <option value="active">فعال</option>
          <option value="disabled">غیرفعال / منقضی</option>
        </select>
      </div>

      <!-- تب ۲: پورت و IP -->
      <div id="tab-network" class="tab-pane">
        <label>پورت اتصال (پشتیبانی‌شده توسط کلودفلر)</label>
        <select id="port">
          <option value="443">443 (امن HTTPS - TLS)</option>
          <option value="2053">2053 (پورت ابری)</option>
          <option value="2083">2083 (پورت ابری)</option>
          <option value="2087">2087 (پورت ابری)</option>
          <option value="8443">8443 (پورت ابری)</option>
        </select>
        <div class="muted">آی‌پی فعال مخزن به صورت خودکار روی کانفیگ‌ها ست می‌شود.</div>
      </div>

      <!-- تب ۳: پروکسی -->
      <div id="tab-proxy" class="tab-pane">
        <label>پروتکل اتصال</label>
        <select id="protocol">
          <option value="VLESS">VLESS (تست‌شده و پرسرعت)</option>
          <option value="Trojan">Trojan (امنیت پیشرفته)</option>
          <option value="Shadowsocks">Shadowsocks (پروتکل سبک)</option>
        </select>
        <div class="muted">انتخاب پروتکل رمزنگاری شده جهت سازگاری با v2rayNG و نایوباکس.</div>
      </div>

      <!-- تب ۴: پیشرفته -->
      <div id="tab-advanced" class="tab-pane">
        <label>حجم مجاز (گیگابایت)</label>
        <input id="traffic" type="number" min="1" value="100" required>
        
        <label>مدت زمان اعتبار (روز)</label>
        <input id="expire" type="number" min="1" value="30" required>
        
        <div class="warning-alert">
          <span>ℹ️ تمامی پارامترهای ارتباطی TLS 1.3 و WebSockets به صورت فعال و استاندارد درج می‌گردند.</span>
        </div>
      </div>
    </form>
  </div>

  <div class="modal-footer">
    <button class="success" onclick="submitUserForm()">ایجاد کاربر</button>
    <button class="danger" onclick="closeUserModal()">انصراف</button>
  </div>
</dialog>

<!-- مودال مدیریت IPها -->
<dialog id="ip-dialog">
  <div class="modal-header">
    <h2 style="margin:0;color:var(--gold);">مدیریت مخزن IP و پورت (Clean IPs)</h2>
    <button class="outline" style="padding:6px 10px;margin:0;" onclick="document.getElementById('ip-dialog').close()">✕</button>
  </div>
  <div class="modal-body">
    <label>ثبت و فعال‌سازی یک IP تمیز</label>
    <input id="ip-input" placeholder="مثال: 104.16.132.229">
    <button class="teal" onclick="saveIp()">ثبت و اعمال فوری</button>

    <label style="margin-top:15px;display:block;">وارد کردن دسته‌جمعی IPها (هر خط یک IP)</label>
    <textarea id="bulk-ips" placeholder="104.16.132.229&#10;104.17.1.1"></textarea>
    <div class="row">
      <button class="teal" onclick="importIps()">بارگذاری گروهی</button>
      <button class="outline" onclick="getCloudflareRanges()">دریافت رنج‌های رسمی کلودفلر</button>
    </div>
    
    <div id="range-output" class="muted" style="margin:10px 0;"></div>
    
    <h3 style="margin-top:20px;">IPهای ذخیره‌شده در مخزن</h3>
    <div id="ip-list">در حال بارگذاری...</div>
  </div>
  <div class="modal-footer">
    <button class="outline" onclick="document.getElementById('ip-dialog').close()">بستن</button>
  </div>
</dialog>

</main>

<script>
const currentHost = ${safeHost};
let usersCache = [];
let ipsCache = [];

async function api(path, options={}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "خطای درخواست سرور");
  return data;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[c]);
}

function toggleConfigBody(id) {
  document.getElementById(id).classList.toggle("show");
}

function switchTab(e, tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  e.target.classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

function setPreset(len, intVal) {
  document.getElementById("frag-len-input").value = len;
  document.getElementById("frag-int-input").value = intVal;
  alert("تنظیمات فرگمنت اپراتور اعمال شد. برای ذخیره روی دکمه ذخیره کلیک کنید.");
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
    if (!isToggleOnly) {
      alert(res.message || "تنظیمات ECH با موفقیت ذخیره شد.");
      toggleConfigBody('ech-body');
    }
  } catch(e) {
    alert("خطا در ذخیره ECH: " + e.message);
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
    if (!isToggleOnly) {
      alert(res.message || "تنظیمات فرگمنت ذخیره شد.");
      toggleConfigBody('frag-body');
    }
  } catch(e) {
    alert("خطا در ذخیره فرگمنت: " + e.message);
  }
}

async function loadAll() {
  try {
    const data = await api("/api/users");
    usersCache = data.users || [];
    ipsCache = data.savedIps || [];
    
    document.getElementById("active-ip").textContent = "IP فعال سیستم: " + data.activeCleanIp;
    document.getElementById("total").textContent = data.metrics.total;
    document.getElementById("active").textContent = data.metrics.active;
    document.getElementById("expired").textContent = data.metrics.expired;
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

    renderUsers();
    renderIps();
  } catch(e) {
    alert("خطا در دریافت اطلاعات: " + e.message);
  }
}

function renderUsers() {
  const root = document.getElementById("users-list");

  if (!usersCache.length) {
    root.innerHTML = '<div class="card" style="text-align:center;padding:30px;">هنوز کاربری ثبت نشده است. از دکمه بالا برای ایجاد کاربر استفاده کنید.</div>';
    return;
  }

  root.innerHTML = usersCache.map(u => {
    const sub = "/sub/" + encodeURIComponent(u.username);
    const yaml = "/yaml/" + encodeURIComponent(u.username);
    const isActive = u.status !== "disabled";
    const statusText = isActive ? "فعال" : "غیرفعال";
    const statusColor = isActive ? "var(--green)" : "var(--red)";

    return '<article class="user-card">' +
      '<div class="row"><h2>' + esc(u.username) + '</h2><span style="color:' + statusColor + ';font-weight:bold;">' + statusText + '</span></div>' +
      '<p class="muted">پروتکل: ' + esc(u.protocol) +
      ' | پورت: ' + esc(u.port) +
      ' | حجم: ' + esc(u.traffic) +
      ' | اعتبار: ' + esc(u.expire) + '</p>' +
      '<div class="row" style="margin-top:12px;">' +
        '<div>' +
          '<a class="button blue" href="' + sub + '" target="_blank">ساب‌سکرپشن متنی</a>' +
          '<a class="button outline" href="' + yaml + '" target="_blank">YAML</a>' +
        '</div>' +
        '<div>' +
          '<button class="outline" onclick="editUserModal(\\'' + esc(u.id) + '\\')">ویرایش</button>' +
          '<button class="danger" onclick="deleteUser(\\'' + esc(u.id) + '\\')">حذف</button>' +
        '</div>' +
      '</div>' +
      '</article>';
  }).join("");
}

function openUserModal() {
  document.getElementById("user-form").reset();
  document.getElementById("edit-id").value = "";
  document.getElementById("username").disabled = false;
  document.getElementById("modal-title").textContent = "ایجاد کاربر جدید";
  document.getElementById("user-modal").showModal();
}

function closeUserModal() {
  document.getElementById("user-modal").close();
}

function editUserModal(id) {
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
  document.getElementById("modal-title").textContent = "ویرایش مشخصات کاربر";
  document.getElementById("user-modal").showModal();
}

async function submitUserForm() {
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
    alert(result.message || "عملیات با موفقیت انجام شد.");
    closeUserModal();
    loadAll();
  } catch(e) {
    alert("خطا: " + e.message);
  }
}

async function deleteUser(id) {
  if (!confirm("آیا از حذف این کاربر اطمینان دارید؟")) return;

  try {
    await api("/api/users/" + encodeURIComponent(id), {method:"DELETE"});
    loadAll();
  } catch(e) {
    alert("خطا در حذف کاربر: " + e.message);
  }
}

function openIpsModal() {
  document.getElementById("ip-dialog").showModal();
  renderIps();
}

function renderIps() {
  const root = document.getElementById("ip-list");

  if (!ipsCache.length) {
    root.innerHTML = '<p class="muted">مخزن IP خالی است.</p>';
    return;
  }

  root.innerHTML = ipsCache.map(item =>
    '<div class="ip-item"><code>' + esc(item.ip) + '</code>' +
    '<div><button class="teal" onclick="selectIp(\\'' + esc(item.ip) + '\\')">انتخاب فعال</button>' +
    '<button class="danger" onclick="deleteIp(\\'' + esc(item.id) + '\\')">حذف</button></div></div>'
  ).join("");
}

async function saveIp() {
  const ip = document.getElementById("ip-input").value.trim();
  if (!ip) return alert("لطفاً یک IP معتبر وارد کنید.");

  try {
    await api("/api/set-clean-ip", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ip})
    });
    document.getElementById("ip-input").value = "";
    await loadAll();
    alert("IP با موفقیت ذخیره و فعال شد.");
  } catch(e) {
    alert("خطا: " + e.message);
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
    alert("تعداد " + data.saved + " IP با موفقیت اضافه شد.");
  } catch(e) {
    alert("خطا در وارد کردن IPها: " + e.message);
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
    alert("IP فعال سیستم تغییر یافت.");
  } catch(e) {
    alert("خطا: " + e.message);
  }
}

async function deleteIp(id) {
  if (!confirm("آیا این IP از مخزن حذف شود؟")) return;

  try {
    await api("/api/delete-ip/" + encodeURIComponent(id), {
      method:"DELETE"
    });
    loadAll();
  } catch(e) {
    alert("خطا: " + e.message);
  }
}

async function getCloudflareRanges() {
  const root = document.getElementById("range-output");
  root.textContent = "در حال دریافت رنج‌های رسمی...";

  try {
    data = await api("/api/cloudflare-ranges");
    const ips = [...data.ipv4, ...data.ipv6];

    document.getElementById("bulk-ips").value = ips.join("\\n");
    root.textContent = "رنج‌ها دریافت شدند: " + data.ipv4.length + " محدوده IPv4 و " + data.ipv6.length + " محدوده IPv6.";
  } catch(e) {
    root.textContent = "خطا در دریافت رنج‌ها: " + e.message;
  }
}

loadAll();
</script>
</body>
</html>`;
}
