import panelHtml from './index.html';
import panelJs from './panel.js';

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
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, username TEXT, uuid TEXT, protocol TEXT,
          traffic TEXT, expire TEXT, port TEXT, tls TEXT, adblock TEXT, adult_block TEXT, status TEXT
        )
      `).run();
    } catch (error) {
      return json({ success: false, error: "خطای آماده‌سازی دیتابیس." }, 500);
    }

    // احراز هویت مدیریت
    if (path.startsWith("/api/") || path === "/") {
      const adminUser = env.ADMIN_USER;
      const adminPass = env.ADMIN_PASSWORD;

      if (!adminUser || !adminPass) {
        return new Response("خطای امنیتی: متغیرهای محیطی ADMIN_USER و ADMIN_PASSWORD تنظیم نشده‌اند.", { status: 500 });
      }

      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Basic ")) {
        return new Response("لطفاً اطلاعات ورود را وارد کنید.", {
          status: 401,
          headers: { "WWW-Authenticate": 'Basic realm="KING PANEL"' }
        });
      }

      try {
        const credentials = atob(authHeader.split(" ")[1]);
        const [username, password] = credentials.split(":");
        if (username !== adminUser || password !== adminPass) {
          return new Response("دسترسی غیرمجاز", { status: 401 });
        }
      } catch {
        return new Response("خطا در رمزگشایی احراز هویت", { status: 400 });
      }
    }

    // تحویل فایل جداگانه کدهای فرانت‌اند (JavaScript)
    if (path === "/panel.js") {
      return new Response(panelJs, {
        headers: { "Content-Type": "application/javascript; charset=UTF-8" }
      });
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

    // ذخیره تنظیمات ECH
    if (path === "/api/set-ech" && method === "POST") {
      const body = await readJson(request);
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('ech_enabled', ?)").bind(body.enabled ? "true" : "false").run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('ech_value', ?)").bind(String(body.value || "")).run();
      return json({ success: true, message: "تنظیمات ECH ذخیره شد." });
    }

    // ذخیره تنظیمات Fragment
    if (path === "/api/set-fragment" && method === "POST") {
      const body = await readJson(request);
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_enabled', ?)").bind(body.enabled ? "true" : "false").run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_len', ?)").bind(String(body.length || "")).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_int', ?)").bind(String(body.interval || "")).run();
      return json({ success: true, message: "تنظیمات فرگمنت ذخیره شد." });
    }

    // ساب‌سکرپشن‌ها
    if ((path.startsWith("/sub/") || path.startsWith("/yaml/")) && method === "GET") {
      const username = decodeURIComponent(path.split("/")[2] || "");
      const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      if (!user || user.status === "disabled") return new Response("کاربر یافت نشد یا غیرفعال است", { status: 404 });

      const port = Number(user.port || 443);
      const protocol = (user.protocol || "VLESS").toLowerCase();
      const name = encodeURIComponent(user.username);
      let config = "";

      const fragmentParam = fragEnabled ? `&packet=tls&length=${fragLen}&interval=${fragInt}` : "";
      const echParam = (echEnabled && protocol !== "shadowsocks") ? `&ech=${encodeURIComponent(echValue)}` : "";

      if (protocol === "vless") {
        config = `vless://${user.uuid}@${activeCleanIp}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(connectionHost)}&fp=chrome&type=ws&host=${encodeURIComponent(connectionHost)}&path=%2F%3Fed%3D2048${fragmentParam}${echParam}#${name}`;
      } else if (protocol === "trojan") {
        config = `trojan://${user.uuid}@${activeCleanIp}:${port}?security=tls&sni=${encodeURIComponent(connectionHost)}&type=ws&host=${encodeURIComponent(connectionHost)}&path=%2F%3Fed%3D2048${fragmentParam}${echParam}#${name}`;
      } else if (protocol === "shadowsocks" || protocol === "ss") {
        const auth = btoa(`chacha20-ietf-poly1305:${user.uuid}`);
        config = `ss://${auth}@${activeCleanIp}:${port}#${name}`;
      }

      if (path.startsWith("/yaml/")) {
        const yaml = [
          "proxies:",
          `  - name: "${yamlEscape(user.username)}"`,
          `    type: ${protocol}`,
          `    server: "${yamlEscape(activeCleanIp)}"`,
          `    port: ${port}`,
          protocol === "vless" ? `    uuid: "${user.uuid}"` : `    password: "${user.uuid}"`,
          "    network: ws",
          "    tls: true",
          `    servername: "${yamlEscape(connectionHost)}"`,
          "    ws-opts:",
          '      path: "/?ed=2048"',
          "      headers:",
          `        Host: "${yamlEscape(connectionHost)}"`,
          "    client-fingerprint: chrome"
        ].join("\n");
        return new Response(yaml, { headers: { "Content-Type": "text/yaml; charset=UTF-8" } });
      }

      return new Response(btoa(unescape(encodeURIComponent(config))), { headers: { "Content-Type": "text/plain; charset=UTF-8" } });
    }

    // لیست کاربران و اطلاعات عمومی
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
        echSettings: { enabled: echEnabled, value: echValue },
        fragmentSettings: { enabled: fragEnabled, length: fragLen, interval: fragInt },
        metrics: {
          total: (usersResult.results || []).length,
          active: (usersResult.results || []).filter(u => u.status === 'active').length,
          disabled: (usersResult.results || []).filter(u => u.status === 'disabled').length
        }
      });
    }

    // افزودن یا ویرایش کاربر
    if (path === "/api/users" && method === "POST") {
      const body = await readJson(request);
      const rawName = String(body.username || "").trim();
      const username = rawName.toUpperCase().startsWith("👑KING_") ? rawName : "👑KING_" + rawName;
      const protocol = String(body.protocol || "VLESS");
      const port = String(body.port || "443");
      const traffic = `${Number(body.traffic ?? 100)} GB`;
      const expire = `${Number(body.expire ?? 30)} روز`;
      const status = body.status === "disabled" ? "disabled" : "active";

      if (body.id) {
        await env.DB.prepare("UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, status = ? WHERE id = ?").bind(protocol, traffic, expire, port, status, String(body.id)).run();
        return json({ success: true, message: "کاربر ویرایش شد." });
      }

      const id = "usr_" + crypto.randomUUID();
      const uuid = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?)").bind(id, username, uuid, protocol, traffic, expire, port, status).run();
      return json({ success: true, message: "کاربر جدید ثبت شد." });
    }

    // تغییر وضعیت یا حذف کاربر
    if (path.startsWith("/api/users/status/") && method === "POST") {
      const id = decodeURIComponent(path.slice("/api/users/status/".length));
      const body = await readJson(request);
      await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(body?.status === "disabled" ? "disabled" : "active", id).run();
      return json({ success: true });
    }

    if (path.startsWith("/api/users/regen/") && method === "POST") {
      const id = decodeURIComponent(path.slice("/api/users/regen/".length));
      const newUuid = crypto.randomUUID();
      await env.DB.prepare("UPDATE users SET uuid = ? WHERE id = ?").bind(newUuid, id).run();
      return json({ success: true, uuid: newUuid });
    }

    if (path.startsWith("/api/users/") && method === "DELETE") {
      const id = decodeURIComponent(path.slice("/api/users/".length));
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
      return json({ success: true });
    }

    // مدیریت IPها
    if (path === "/api/set-clean-ip" && method === "POST") {
      const body = await readJson(request);
      const ip = String(body?.ip || "").trim();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind("ip_" + ip.replace(/[^a-zA-Z0-9]/g, "_"), ip).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();
      return json({ success: true, activeCleanIp: ip });
    }

    if (path === "/api/import-ips" && method === "POST") {
      const body = await readJson(request);
      const input = [...new Set(String(body?.ips || "").split(/[\s,;]+/).map(i => i.trim()).filter(Boolean))];
      for (const ip of input) {
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind("ip_" + ip.replace(/[^a-zA-Z0-9]/g, "_"), ip).run();
      }
      return json({ success: true, saved: input.length });
    }

    if (path === "/api/select-clean-ip" && method === "POST") {
      const body = await readJson(request);
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(body.ip).run();
      return json({ success: true });
    }

    if (path.startsWith("/api/delete-ip/") && method === "DELETE") {
      const key = decodeURIComponent(path.slice("/api/delete-ip/".length));
      await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
      return json({ success: true });
    }

    if (path === "/api/cloudflare-ranges" && method === "GET") {
      const [r4, r6] = await Promise.all([fetch("https://www.cloudflare.com/ips-v4"), fetch("https://www.cloudflare.com/ips-v6")]);
      return json({ success: true, ipv4: (await r4.text()).trim().split(/\s+/), ipv6: (await r6.text()).trim().split(/\s+/) });
    }

    // نمایش صفحه اصلی (ترکیب هاست و لینک فرانت‌اند)
    return new Response(panelHtml.replace('__HOST__', JSON.stringify(host)).replace('__PUBLIC_URL__', JSON.stringify(publicUrl)), {
      headers: { "Content-Type": "text/html; charset=UTF-8" }
    });
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=UTF-8" } });
}
async function readJson(request) { try { return await request.json(); } catch { return null; } }
function yamlEscape(val) { return String(val ?? "").replace(/\\/g, "\\\\").replace(/"/g, '\\"'); }
