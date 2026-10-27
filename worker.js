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

// LANDING PAGE ROUTE
if (path === "/") {
  return html(landingPage());
}

// USER PANEL ROUTE (PUBLIC USER CREATION INTERFACE)
if (path === "/user") {
  return html(userPortal(host, publicUrlFunc(host, env)));
}

// PUBLIC USER CREATION API (Restricted: creates user only, no admin controls/settings/deletions)
if (path === "/api/public/create-user" && method === "POST") {
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
  const status = "active";

  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (existing) return json({ error: "این نام کاربری قبلاً ثبت شده است." }, 409);

  const id = "usr_" + crypto.randomUUID();
  const uuid = crypto.randomUUID();

  await env.DB.prepare(`    
    INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status)    
    VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?)    
  `).bind(id, username, uuid, protocol, traffic, expire, port, status).run();

  const pUrl = env.PANEL_PUBLIC_URL || `https://${host}`;
  return json({ 
    success: true, 
    message: "کاربر جدید با موفقیت ثبت شد.", 
    username, 
    subUrl: `${pUrl}/sub/${encodeURIComponent(username)}`,
    yamlUrl: `${pUrl}/yaml/${encodeURIComponent(username)}`,
    uuid 
  });
}

// OWNER LOGIN / DASHBOARD AUTHENTICATION & API PROTECTION
if (path === "/owner" || path.startsWith("/api/")) {    
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
      <title>ورود مدیریت - KING PANEL</title>    
      <style>    
        :root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--purple:#8b5cf6;--text:#f3f4f6;--muted:#9ca3af}    
        body{margin:0;padding:0;background:radial-gradient(circle at center, #111827 0%, var(--bg) 100%);color:var(--text);font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}    
        .login-card{background:var(--card);border:1px solid rgba(245,158,11,0.3);border-radius:24px;padding:40px;width:100%;max-width:420px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(139,92,246,0.15);position:relative;overflow:hidden;animation:fadeIn 0.5s ease-out}    
        @keyframes fadeIn{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:translateY(0)}}    
        .login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg, var(--gold), var(--purple))}    
        h1{color:var(--gold);font-size:24px;margin-bottom:10px;text-shadow:0 0 15px rgba(245,158,11,0.3)}    
        p{color:var(--muted);font-size:14px;margin-bottom:25px}    
        .badge{background:rgba(245,158,11,0.12);color:var(--gold);padding:6px 14px;border-radius:20px;font-size:12px;display:inline-block;margin-bottom:20px;border:1px solid rgba(245,158,11,0.3);font-weight:bold}    
        .input-group{position:relative;margin-bottom:16px}    
        input{width:100%;padding:12px 16px;background:#030508;color:white;border:1px solid var(--border);border-radius:10px;text-align:right;font-size:14px;transition:0.2s}    
        input:focus{border-color:var(--gold);outline:none;box-shadow:0 0 15px rgba(245,158,11,0.25)}    
        .toggle-password{position:absolute;left:14px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--muted);cursor:pointer;font-size:13px}    
        .toggle-password:hover{color:var(--gold)}    
        .btn{width:100%;background:linear-gradient(135deg, var(--gold), #d97706);color:#111;border:0;padding:12px;border-radius:10px;font-weight:bold;cursor:pointer;font-size:15px;margin-top:10px;box-shadow:0 4px 15px rgba(245,158,11,0.3);transition:0.2s}    
        .btn:hover{filter:brightness(1.1);transform:scale(1.02)}    
        .back-link{display:inline-block;margin-top:20px;color:var(--muted);font-size:13px;text-decoration:none;transition:0.2s}    
        .back-link:hover{color:var(--gold)}    
        .error-msg{color:#ef4444;font-size:13px;margin-top:12px;display:none;animation:shake 0.3s}    
        @keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}    
      </style>    
      </head>    
      <body>    
        <div class="login-card">    
          <span class="badge">👑 بخش مدیریت ارشد 👑</span>    
          <h1>احراز هویت ادمین</h1>    
          <p>لطفاً برای ورود به پنل مدیریت، اطلاعات دسترسی خود را وارد کنید.</p>    
          <form onsubmit="handleLogin(event)">    
            <div class="input-group">    
              <input type="text" id="username" placeholder="نام کاربری ادمین" required autocomplete="username">    
            </div>    
            <div class="input-group">    
              <input type="password" id="password" placeholder="کلمه عبور" required autocomplete="current-password">    
              <button type="button" class="toggle-password" onclick="togglePass()">👁️</button>    
            </div>    
            <button type="submit" class="btn">ورود به پنل مدیریت</button>    
            <div id="error" class="error-msg">نام کاربری یا کلمه عبور اشتباه است.</div>    
          </form>    
          <a href="/" class="back-link">← بازگشت به صفحه اصلی</a>    
        </div>    
        <script>      
        function togglePass() {
          const p = document.getElementById('password');
          p.type = p.type === 'password' ? 'text' : 'password';
        }
        async function handleLogin(e) {      
          e.preventDefault();      
          const u = document.getElementById('username').value;      
          const p = document.getElementById('password').value;      
          const header = 'Basic ' + btoa(u + ':' + p);      
          try {      
            const res = await fetch('/owner', { headers: { 'Authorization': header } });      
            if (res.ok) {      
              window.location.href = '/owner';      
            } else {      
              document.getElementById('error').style.display = 'block';      
            }      
          } catch {      
            document.getElementById('error').style.display = 'block';      
          }      
        }      
        </script>    
      </body>    
      </html>    
    `, {    
      status: 401,    
      headers: {    
        "Content-Type": "text/html; charset=UTF-8",    
        "WWW-Authenticate": 'Basic realm="KING PANEL OWNER"'    
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

// دریافت تنظیمات از دیتابیس    
const [activeRow, fragEnabledRow, fragLenRow, fragIntRow] = await Promise.all([    
  env.DB.prepare("SELECT value FROM settings WHERE key = 'clean_ip'").first().catch(() => null),    
  env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_enabled'").first().catch(() => null),    
  env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first().catch(() => null),    
  env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first().catch(() => null)    
]);    

const publicUrl = env.PANEL_PUBLIC_URL || `https://${host}`;    
const connectionHost = env.CONNECTION_HOST || host;    
const activeCleanIp = activeRow?.value || connectionHost;    
    
const fragEnabled = fragEnabledRow?.value === "true";    
const fragLen = fragLenRow?.value || "100-200";    
const fragInt = fragIntRow?.value || "10-20";    

// API: SAVE FRAGMENT SETTINGS    
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

// SUBSCRIPTION: VLESS / TROJAN / SHADOWSOCKS    
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

  const fragmentParam = fragEnabled ? `&packet=tls&length=${fragLen}&interval=${fragInt}` : "";    

  if (protocol === "vless") {    
    config =    
      `vless://XpnTeam-53@199.232.78.160:443` +    
      `?pcs=cd6e838b9bfe31cab8b3d5c858b0d6223fe84ece236c1fdb281be93c302e1e6e` +    
      `&path=%2F` +    
      `&security=tls` +    
      `&encryption=none` +    
      `&insecure=0` +    
      `&host=Appxdn.global.ssl.fastly.net` +    
      `&type=ws` +    
      `&allowInsecure=0` +    
      `&sni=cdn.akamai.steamstatic.com` +    
      fragmentParam +    
      `#${name}`;    
  } else if (protocol === "trojan") {    
    config =    
      `trojan://${user.uuid}@${activeCleanIp}:${port}` +    
      `?security=tls` +    
      `&sni=${encodeURIComponent(connectionHost)}` +    
      `&type=ws` +    
      `&host=${encodeURIComponent(connectionHost)}` +    
      `&path=%2F%3Fed%3D2048` +    
      fragmentParam +    
      `#${name}`;    
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
      "    ws-opts:",    
      '      path: "/?ed=2048"',    
      "      headers:",    
      `        Host: "${yamlEscape(connectionHost)}"`,    
      "    client-fingerprint: chrome",    
      fragEnabled ? `    fragment: tls` : "",    
      fragEnabled ? `    fragment-length: ${fragLen}` : "",    
      fragEnabled ? `    fragment-interval: ${fragInt}` : ""    
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

// USER STATUS    
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

// GET USERS, SAVED IPS & SETTINGS    
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

// ADD OR EDIT USER    
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

    await env.DB.prepare(`    
      UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, status = ? WHERE id = ?    
    `).bind(protocol, traffic, expire, port, status, String(body.id)).run();    

    return json({ success: true, message: "کاربر با موفقیت ویرایش شد." });    
  }    

  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();    
  if (existing) return json({ error: "این نام کاربری قبلاً ثبت شده است." }, 409);    

  const id = "usr_" + crypto.randomUUID();    
  const uuid = crypto.randomUUID();    

  await env.DB.prepare(`    
    INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status)    
    VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', 'on', 'on', ?)    
  `).bind(id, username, uuid, protocol, traffic, expire, port, status).run();    

  return json({ success: true, message: "کاربر جدید ثبت شد." });    
}    

// REGENERATE UUID    
if (path.startsWith("/api/users/regen/") && method === "POST") {    
  const id = decodeURIComponent(path.slice("/api/users/regen/".length));    
  if (!id) return json({ error: "شناسه نامعتبر است." }, 400);    

  const newUuid = crypto.randomUUID();    
  await env.DB.prepare("UPDATE users SET uuid = ? WHERE id = ?").bind(newUuid, id).run();    
  return json({ success: true, message: "UUID کاربر با موفقیت بازسازی شد.", uuid: newUuid });    
}    

// TOGGLE USER STATUS    
if (path.startsWith("/api/users/status/") && method === "POST") {    
  const id = decodeURIComponent(path.slice("/api/users/status/".length));    
  const body = await readJson(request);    
  const newStatus = body?.status === "disabled" ? "disabled" : "active";    

  await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(newStatus, id).run();    
  return json({ success: true, message: "وضعیت کاربر به‌روز شد." });    
}    

// DELETE USER    
if (path.startsWith("/api/users/") && method === "DELETE") {    
  const id = decodeURIComponent(path.slice("/api/users/".length));    
  if (!id) return json({ error: "شناسه نامعتبر است." }, 400);    

  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();    
  return json({ success: true, message: "کاربر حذف شد." });    
}    

// SET CLEAN IP    
if (path === "/api/set-clean-ip" && method === "POST") {    
  const body = await readJson(request);    
  const ip = String(body?.ip || "").trim();    
  if (!isValidIp(ip)) return json({ error: "قالب IP معتبر نیست." }, 400);    

  await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(makeIpKey(ip), ip).run();    
  await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();    

  return json({ success: true, activeCleanIp: ip });    
}    

// IMPORT IPS    
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

// SELECT SAVED IP    
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

// DELETE SAVED IP    
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

// CLOUDFLARE RANGES    
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

function publicUrlFunc(host, env) {
return env.PANEL_PUBLIC_URL || `https://${host}`;
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

function landingPage() {
return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ورود به KING PANEL</title>
<style>
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--purple:#8b5cf6;--text:#f3f4f6;--muted:#9ca3af;--teal:#14b8a6}
*{box-sizing:border-box}
body{margin:0;padding:20px;background:radial-gradient(circle at center, #111827 0%, var(--bg) 100%);color:var(--text);font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{width:100%;max-width:850px;text-align:center}
.badge{background:rgba(245,158,11,0.12);color:var(--gold);padding:8px 18px;border-radius:30px;font-size:13px;display:inline-block;margin-bottom:25px;border:1px solid rgba(245,158,11,0.3);font-weight:bold;box-shadow:0 0 20px rgba(245,158,11,0.15)}
h1{font-size:clamp(28px, 5vw, 42px);color:var(--gold);margin:0 0 10px 0;text-shadow:0 0 25px rgba(245,158,11,0.3)}
p.subtitle{color:var(--muted);font-size:clamp(14px, 2vw, 16px);margin-bottom:45px}
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:25px;margin-top:20px}
.portal-card{background:var(--card);border:1px solid var(--border);border-radius:24px;padding:40px 30px;text-decoration:none;color:var(--text);display:flex;flex-direction:column;align-items:center;transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);position:relative;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
.portal-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;transition:0.3s}
.owner-card::before{background:linear-gradient(90deg, var(--gold), var(--purple))}
.user-card::before{background:linear-gradient(90deg, var(--teal), var(--purple))}
.portal-card:hover{transform:translateY(-8px);border-color:rgba(245,158,11,0.5);box-shadow:0 20px 40px rgba(0,0,0,0.7), 0 0 30px rgba(139,92,246,0.2)}
.icon{font-size:52px;margin-bottom:20px;filter:drop-shadow(0 0 10px rgba(255,255,150,0.2))}
.portal-card h2{font-size:24px;margin:0 0 12px 0}
.owner-card h2{color:var(--gold)}
.user-card h2{color:var(--teal)}
.portal-card p{color:var(--muted);font-size:14px;margin:0;line-height:1.6}
.btn-action{margin-top:25px;padding:10px 24px;border-radius:12px;font-weight:bold;font-size:14px;transition:0.2s}
.owner-card .btn-action{background:linear-gradient(135deg, var(--gold), #d97706);color:#111;box-shadow:0 4px 15px rgba(245,158,11,0.3)}
.user-card .btn-action{background:linear-gradient(135deg, var(--teal), #0d9488);color:#111;box-shadow:0 4px 15px rgba(20,184,166,0.3)}
.portal-card:hover .btn-action{filter:brightness(1.1);transform:scale(1.05)}
</style>
</head>
<body>
<div class="container">
  <span class="badge">👑 KING PANEL PLATFORM 👑</span>
  <h1>به پنل قدرتمند کینگ خوش آمدید</h1>
  <p class="subtitle">لطفاً برای ورود به بخش مدیریت یا پنل کاربری، یکی از گزینه‌های زیر را انتخاب کنید.</p>
  
  <div class="cards-grid">
    <a href="/owner" class="portal-card owner-card">
      <div class="icon">👑</div>
      <h2>OWNER</h2>
      <p>ورود به پنل مدیریت ارشد جهت کنترل کاربران، تنظیمات پروتکل‌ها و مدیریت مخزن IP</p>
      <span class="btn-action">ورود به مدیریت</span>
    </a>

    <a href="/user" class="portal-card user-card">
      <div class="icon">👤</div>
      <h2>USER</h2>
      <p>ثبت نام و ایجاد اشتراک جدید با دسترسی به لینک‌های اختصاصی اتصال</p>
      <span class="btn-action">ورود به بخش کاربر</span>
    </a>
  </div>
</div>
</body>
</html>`;
}

function userPortal(host, publicUrl) {
const safePublicUrl = JSON.stringify(publicUrl);
return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ثبت‌نام کاربر - KING PANEL</title>
<style>
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--teal:#14b8a6;--purple:#8b5cf6;--text:#f3f4f6;--muted:#9ca3af}
*{box-sizing:border-box}
body{margin:0;padding:20px;background:radial-gradient(circle at top, #111827 0%, var(--bg) 100%);color:var(--text);font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}
main{width:100%;max-width:550px}
header{background:var(--card);border:1px solid rgba(20,184,166,0.3);border-radius:18px;padding:20px 25px;display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
h1{font-size:20px;color:var(--teal);margin:0}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:25px;box-shadow:0 10px 30px rgba(0,0,0,0.5);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg, var(--teal), var(--purple))}
label{display:block;margin-top:12px;font-size:13px;color:var(--muted)}
input,select{width:100%;padding:11px;background:var(--bg);color:white;border:1px solid var(--border);border-radius:10px;margin-top:5px;font-family:inherit}
input:focus,select:focus{border-color:var(--teal);outline:none;box-shadow:0 0 10px rgba(20,184,166,0.2)}
button.btn{width:100%;background:linear-gradient(135deg, var(--teal), #0d9488);color:#111;border:0;padding:12px;border-radius:10px;font-weight:bold;cursor:pointer;font-size:15px;margin-top:20px;transition:0.2s}
button.btn:hover{filter:brightness(1.1)}
.button{border:0;border-radius:10px;padding:8px 14px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block;font-size:12px;background:#111827;color:white;border:1px solid var(--border);transition:0.2s}
.button:hover{border-color:var(--teal)}
#result-box{display:none;margin-top:20px;background:#030508;border:1px solid rgba(20,184,166,0.4);border-radius:12px;padding:15px}
.result-row{margin-bottom:10px;font-size:13px;word-break:break-all}
.copy-btn{background:var(--teal);color:#111;border:0;padding:6px 12px;border-radius:8px;font-weight:bold;cursor:pointer;font-size:12px;margin-top:5px}
.copy-btn:hover{filter:brightness(1.1)}
</style>
</head>
<body>
<main>
  <header>
    <h1>👤 ساخت اشتراک جدید</h1>
    <a href="/" class="button">← صفحه اصلی</a>
  </header>
  
  <div class="card">
    <form id="public-user-form">
      <label>نام کاربری دلخواه</label>
      <input id="username" required placeholder="مثلاً ali">
      
      <label>انتخاب پروتکل</label>
      <select id="protocol">
        <option>VLESS</option>
        <option>Trojan</option>
        <option>Shadowsocks</option>
      </select>
      
      <label>پورت اتصال</label>
      <select id="port">
        <option>443</option>
        <option>2053</option>
        <option>2083</option>
        <option>2087</option>
        <option>8443</option>
      </select>

      <button type="submit" class="btn">ثبت‌نام و ایجاد سرویس</button>
    </form>

    <div id="result-box">
      <h3 style="color:var(--teal);margin-top:0;font-size:16px;">✨ حساب شما با موفقیت ساخته شد!</h3>
      <div class="result-row"><b>نام کاربری:</b> <span id="res-user"></span></div>
      <div class="result-row"><b>لینک ساب‌سکرپشن:</b><br><input id="res-sub" readonly style="margin-top:4px;font-size:11px;"> <button class="copy-btn" onclick="copyVal('res-sub', 'لینک ساب کپی شد!')">کپی لینک ساب</button></div>
      <div class="result-row" style="margin-top:12px;"><b>لینک ساب YAML (کلاش):</b><br><input id="res-yaml" readonly style="margin-top:4px;font-size:11px;"> <button class="copy-btn" onclick="copyVal('res-yaml', 'لینک YAML کپی شد!')">کپی لینک YAML</button></div>
    </div>
  </div>
</main>
<script>
const publicPanelUrl = ${safePublicUrl};
document.getElementById('public-user-form').addEventListener('submit', async e => {
  e.preventDefault();
  const username = document.getElementById('username').value.trim();
  const protocol = document.getElementById('protocol').value;
  const port = document.getElementById('port').value;

  try {
    const res = await fetch('/api/public/create-user', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username, protocol, port, traffic: 100, expire: 30 })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'خطا در ثبت‌نام');

    document.getElementById('res-user').textContent = data.username;
    document.getElementById('res-sub').value = data.subUrl;
    document.getElementById('res-yaml').value = data.yamlUrl;
    document.getElementById('result-box').style.display = 'block';
    document.getElementById('public-user-form').reset();
  } catch(err) {
    alert('خطا: ' + err.message);
  }
});

function copyVal(elementId, msg) {
  const el = document.getElementById(elementId);
  el.select();
  navigator.clipboard.writeText(el.value).then(() => alert(msg)).catch(() => alert('خطا در کپی کردن'));
}
</script>
</body>
</html>`;
}

function dashboard(host, publicUrl) {
const safeHost = JSON.stringify(host);
const safePublicUrl = JSON.stringify(publicUrl);
return `<!doctype html>

<html lang="fa" dir="rtl">      
<head>      
<meta charset="utf-8">      
<meta name="viewport" content="width=device-width,initial-scale=1">      
<title>مدیریت - KING PANEL</title>      
<style>      
:root{--bg:#030508;--card:#0a0e17;--border:#1e2634;--gold:#f59e0b;--text:#f3f4f6;--muted:#9ca3af;--green:#10b981;--red:#ef4444;--purple:#8b5cf6;--teal:#14b8a6}      
*{box-sizing:border-box}      
body{margin:0;padding:15px;background:radial-gradient(circle at top, #111827 0%, var(--bg) 100%);color:var(--text);font-family:system-ui,sans-serif}      
main{max-width:1100px;margin:auto}      
header,.card,.toolbar,.box{background:var(--card);border:1px solid rgba(139,92,246,0.2);border-radius:18px;padding:20px;margin-bottom:15px;box-shadow:0 10px 30px rgba(0,0,0,0.5)}      
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}      
h1{font-size:22px;color:var(--gold);margin:0;text-shadow:0 0 10px rgba(245,158,11,0.2)}      
h2{font-size:16px}      
.muted{color:var(--muted);font-size:12px}      
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:15px}      
.stat{background:var(--card);border:1px solid var(--border);padding:16px;border-radius:14px;box-shadow:0 5px 15px rgba(0,0,0,0.3)}      
.stat b{display:block;font-size:22px;color:var(--gold);margin-top:6px}      
.toolbar{display:flex;gap:10px;flex-wrap:wrap}      
input,select,textarea{width:100%;padding:11px;background:var(--bg);color:white;border:1px solid var(--border);border-radius:10px;margin:5px 0 12px;transition:0.2s}      
input:focus,select:focus,textarea:focus{border-color:var(--gold);outline:none;box-shadow:0 0 10px rgba(245,158,11,0.2)}      
textarea{min-height:110px}      
button,.button{border:0;border-radius:10px;padding:10px 16px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block;margin:3px;font-size:13px;transition:0.2s}      
button:hover{filter:brightness(1.1);transform:translateY(-1px)}      
.gold{background:linear-gradient(135deg, var(--gold), #d97706);color:#111;box-shadow:0 4px 12px rgba(245,158,11,0.25)}      
.teal{background:linear-gradient(135deg, var(--teal), #0d9488);color:#111;box-shadow:0 4px 12px rgba(20,184,166,0.25)}      
.outline{background:#111827;color:white;border:1px solid var(--border)}      
.outline:hover{border-color:var(--purple)}      
.danger{background:linear-gradient(135deg, #7f1d1d, #991b1b);color:#fecaca}      
.user{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;margin:12px 0;overflow-wrap:anywhere;box-shadow:0 5px 15px rgba(0,0,0,0.3)}      
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap}      
.tag{font-size:12px;color:var(--green);background:rgba(16,185,129,0.1);padding:4px 10px;border-radius:20px;border:1px solid rgba(16,185,129,0.2)}      
.ip{padding:10px;border-bottom:1px solid var(--border);overflow-wrap:anywhere}      
dialog{width:min(650px,95vw);max-height:90vh;overflow:auto;background:var(--card);color:white;border:1px solid var(--purple);border-radius:18px;box-shadow:0 20px 50px rgba(0,0,0,0.8)}      
dialog::backdrop{background:#000b}    
.config-card { background: #07111e; border: 1px solid rgba(20,184,166,0.3); border-radius: 16px; padding: 18px; margin-bottom: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }    
.config-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }    
.switch { position: relative; display: inline-block; width: 46px; height: 24px; }    
.switch input { opacity: 0; width: 0; height: 0; }    
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #1e2634; transition: .3s; border-radius: 24px; }    
.slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }    
input:checked + .slider { background-color: var(--teal); }    
input:checked + .slider:before { transform: translateX(22px); }    
.config-body { margin-top: 15px; display: none; border-top: 1px solid var(--border); padding-top: 15px; }    
.config-body.show { display: block; }    
.preset-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-top: 10px; }    
.preset-btn { background: #0d1522; border: 1px solid var(--border); color: var(--text); padding: 9px; border-radius: 9px; cursor: pointer; font-size: 11px; text-align: center; transition: 0.2s; }    
.preset-btn:hover { border-color: var(--teal); background: rgba(20,184,166,0.1); }    
</style>    
</head>      
<body>      
<main>      
<header>      
  <h1>👑 KING PANEL <span style="font-size:13px;color:var(--purple);font-weight:normal;">| پنل مدیریت ارشد</span></h1>      
  <div style="display:flex;gap:10px;align-items:center;">
    <div class="tag" id="active-ip">در حال دریافت IP فعال...</div>      
    <a href="/" class="button outline" style="margin:0;padding:6px 12px;font-size:12px;">← صفحه اصلی</a>
  </div>
</header>    
<section class="stats">      
  <div class="stat">کل کاربران<b id="total">0</b></div>      
  <div class="stat">کاربران فعال<b id="active">0</b></div>      
  <div class="stat">غیرفعال<b id="disabled">0</b></div>      
  <div class="stat">IPهای مخزن<b id="ip-total">0</b></div>      
</section>    
<div class="toolbar" style="background:var(--card);border:1px solid var(--border);border-radius:18px;padding:18px;margin-bottom:15px;">      
  <input id="search-input" placeholder="🔍 جستجوی نام کاربری..." oninput="filterUsers()" style="margin:0;flex:2;min-width:200px;">      
  <select id="filter-status" onchange="filterUsers()" style="margin:0;flex:1;min-width:140px;">      
    <option value="all">همه کاربران</option>      
    <option value="active">فقط فعال‌ها</option>      
    <option value="disabled">فقط غیرفعال‌ها</option>      
  </select>      
</div>    
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
    '<button class="danger" onclick="deleteUser(\\'' + esc(u.id) + '\\')">🗑️ حذف</button>' +      
  '</div>' +      
  '</article>';

}).join("");
}

function copyText(text, msg) {
navigator.clipboard.writeText(text).then(() => alert(msg)).catch(() => alert("خطا در کپی کردن."));
}

function openUser() {
document.getElementById("user-form").reset();
document.getElementById("edit-id").value = "";
document.getElementById("username").disabled = false;
document.getElementById("user-title").textContent = "ایجاد کاربر جدید";
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
const payload = {
id: document.getElementById("edit-id").value,
username: document.getElementById("username").value,
protocol: document.getElementById("protocol").value,
port: document.getElementById("port").value,
traffic: document.getElementById("traffic").value,
expire: document.getElementById("expire").value,
status: document.getElementById("status").value
};
try {
await api("/api/users", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(payload) });
document.getElementById("user-dialog").close();
loadAll();
} catch(e) { alert("خطا: " + e.message); }
});

async function deleteUser(id) {
if (!confirm("آیا از حذف این کاربر اطمینان دارید؟")) return;
try {
await api("/api/users/" + encodeURIComponent(id), { method: "DELETE" });
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function toggleUserStatus(id, currentStatus) {
const newStatus = currentStatus === "disabled" ? "active" : "disabled";
try {
await api("/api/users/status/" + encodeURIComponent(id), {
method: "POST",
headers: {"Content-Type": "application/json"},
body: JSON.stringify({ status: newStatus })
});
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function regenUuid(id) {
if (!confirm("آیا می‌خواهید UUID این کاربر را بازسازی کنید؟")) return;
try {
await api("/api/users/regen/" + encodeURIComponent(id), { method: "POST" });
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

function openIps() {
document.getElementById("ip-dialog").showModal();
renderIps();
}

function renderIps() {
const listEl = document.getElementById("ip-list");
if (!ipsCache.length) {
listEl.innerHTML = '<div class="muted">هیچ IP ذخیره‌شده‌ای وجود ندارد.</div>';
return;
}
listEl.innerHTML = ipsCache.map(i =>
'<div class="ip row"><code>' + esc(i.ip) + '</code>' +
'<div><button class="teal" onclick="selectIp(\\'' + esc(i.ip) + '\\')">انتخاب</button>' +
'<button class="danger" onclick="deleteIp(\\'' + esc(i.id) + '\\')">حذف</button></div></div>'
).join("");
}

async function saveIp() {
const ip = document.getElementById("ip-input").value.trim();
if (!ip) return;
try {
await api("/api/set-clean-ip", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ip}) });
document.getElementById("ip-input").value = "";
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function importIps() {
const ips = document.getElementById("bulk-ips").value.trim();
if (!ips) return;
try {
const res = await api("/api/import-ips", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ips}) });
alert(res.saved + " IP با موفقیت ثبت شد.");
document.getElementById("bulk-ips").value = "";
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function selectIp(ip) {
try {
await api("/api/select-clean-ip", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ip}) });
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function deleteIp(id) {
try {
await api("/api/delete-ip/" + encodeURIComponent(id), { method: "DELETE" });
loadAll();
} catch(e) { alert("خطا: " + e.message); }
}

async function getRanges() {
const out = document.getElementById("range-output");
out.textContent = "در حال دریافت محدوده‌ها...";
try {
const res = await api("/api/cloudflare-ranges");
out.textContent = "تعداد رنج IPv4: " + res.ipv4.length + " | تعداد رنج IPv6: " + res.ipv6.length;
} catch(e) {
out.textContent = "خطا در دریافت محدوده‌ها: " + e.message;
}
}

async function openDiagnostics() {
const diagEl = document.getElementById("diag-content");
document.getElementById("diag-dialog").showModal();
diagEl.textContent = "در حال بررسی سیستم...";
try {
const res = await api("/api/diagnostics");
diagEl.innerHTML =
"وضعیت دیتابیس D1: " + res.d1Status + "<br>" +
"تعداد کل کاربران ثبت‌شده: " + res.totalUsers + "<br>" +
"متغیرهای محیطی ادمین: " + (res.environment.hasAdminUser ? "تنظیم شده" : "تنظیم نشده") + "<br>" +
"هاست اتصال: " + res.environment.connectionHost;
} catch(e) {
diagEl.textContent = "خطا در اجرای عیب‌یابی: " + e.message;
}
}

loadAll();
</script>

</body>    
</html>`;    
}
