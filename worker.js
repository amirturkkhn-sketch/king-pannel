export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const host = url.host;

    if (!env.DB) {
      return new Response("خطا: دیتابیس D1 متصل نشده است.", { status: 500 });
    }

    try {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT, uuid TEXT, protocol TEXT, traffic TEXT, expire TEXT, port TEXT, tls TEXT, adblock TEXT, adult_block TEXT, status TEXT)").run();
    } catch(e) {}

    let activeCleanIp = host;
    try {
      const savedIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'clean_ip'").first();
      if (savedIp && savedIp.value) {
        activeCleanIp = savedIp.value;
      }
    } catch(e) {}

    if (path.startsWith("/sub/") && method === "GET") {
      const username = path.split("/")[2];
      const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      if (!user) return new Response("User not found", { status: 404 });

      const uUuid = user.uuid;
      const uPort = user.port || "443";
      const protocol = (user.protocol || "VLESS").toLowerCase();
      const encodedName = encodeURIComponent(user.username);

      let singleConfig = "";
      if (protocol === "vless") {
        singleConfig = "vless://" + uUuid + "@" + activeCleanIp + ":" + uPort + "?encryption=none&security=tls&sni=" + host + "&fp=chrome&type=ws&host=" + host + "&path=%2F%3Fed%3D2048#" + encodedName + "-VLESS";
      } else if (protocol === "trojan") {
        singleConfig = "trojan://" + uUuid + "@" + activeCleanIp + ":" + uPort + "?security=tls&sni=" + host + "&type=ws&host=" + host + "&path=%2F%3Fed%3D2048#" + encodedName + "-Trojan";
      } else if (protocol === "shadowsocks" || protocol === "ss") {
        const auth = btoa("chacha20-ietf-poly1305:" + uUuid);
        singleConfig = "ss://" + auth + "@" + activeCleanIp + ":" + uPort + "#" + encodedName + "-SS";
      } else {
        singleConfig = "vless://" + uUuid + "@" + activeCleanIp + ":" + uPort + "?encryption=none&security=tls&sni=" + host + "&fp=chrome&type=ws&host=" + host + "&path=%2F%3Fed%3D2048#" + encodedName + "-VLESS";
      }

      const encodedBase64 = btoa(String.fromCharCode(...new TextEncoder().encode(singleConfig)));

      return new Response(encodedBase64, {
        headers: { "Content-Type": "text/plain;charset=UTF-8", "Cache-Control": "no-store" }
      });
    }

    if (path.startsWith("/yaml/") && method === "GET") {
      const username = path.split("/")[2];
      const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      if (!user) return new Response("User not found", { status: 404 });

      const uUuid = user.uuid;
      const uPort = user.port || "443";
      const proto = (user.protocol || "vless").toLowerCase();
      
      let yamlContent = "";
      if (proto === "vless") {
        yamlContent = "proxies:\n  - name: \"" + user.username + "-VLESS\"\n    type: vless\n    server: " + activeCleanIp + "\n    port: " + uPort + "\n    uuid: " + uUuid + "\n    network: ws\n    tls: true\n    sni: " + host + "\n    skip-cert-verify: true\n    client-fingerprint: chrome\n    ws-opts:\n      path: \"/?ed=2048\"\n      headers:\n        Host: " + host;
      } else if (proto === "trojan") {
        yamlContent = "proxies:\n  - name: \"" + user.username + "-Trojan\"\n    type: trojan\n    server: " + activeCleanIp + "\n    port: " + uPort + "\n    password: " + uUuid + "\n    network: ws\n    tls: true\n    sni: " + host + "\n    skip-cert-verify: true\n    ws-opts:\n      path: \"/?ed=2048\"\n      headers:\n        Host: " + host;
      } else {
        yamlContent = "proxies:\n  - name: \"" + user.username + "-SS\"\n    type: shadowsocks\n    server: " + activeCleanIp + "\n    port: " + uPort + "\n    password: " + uUuid + "\n    cipher: chacha20-ietf-poly1305";
      }

      return new Response(yamlContent, {
        headers: { "Content-Type": "text/yaml;charset=UTF-8", "Cache-Control": "no-store" }
      });
    }

    if (path.startsWith("/status/") && method === "GET") {
      const username = path.split("/")[2];
      return new Response(generateUserStatusHtml(username, host), {
        headers: { "Content-Type": "text/html;charset=UTF-8" }
      });
    }

    if (path === "/api/users" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT * FROM users").all();
      let ipsList = [];
      try {
        const ipRows = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'ip_%'").all();
        if(ipRows && ipRows.results) {
          ipsList = ipRows.results.map(r => ({ id: r.key, ip: r.value }));
        }
      } catch(e) {}

      return jsonResponse({
        success: true,
        users: results || [],
        activeCleanIp: activeCleanIp,
        savedIps: ipsList,
        metrics: {
          total: (results || []).length,
          active: (results || []).filter(u => u.status === 'active').length,
        }
      });
    }

    if (path === "/api/set-clean-ip" && method === "POST") {
      const body = await request.json();
      const ip = body.ip ? body.ip.trim() : "";
      if (!ip) return jsonResponse({ error: "آی‌پی نامعتبر است." }, 400);

      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)").bind(ip).run();
      const ipKey = "ip_" + ip.replace(/[\.\:]/g, "_");
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(ipKey, ip).run();

      return jsonResponse({ success: true, message: "آی‌پی با موفقیت ثبت شد." });
    }

    if (path.startsWith("/api/delete-ip/") && method === "DELETE") {
      const ipKey = path.split("/")[3];
      await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(ipKey).run();
      return jsonResponse({ success: true });
    }

    if (path === "/api/users" && method === "POST") {
      const body = await request.json();
      let rawName = body.username ? body.username.trim() : "";
      if (!rawName) return jsonResponse({ error: "نام کاربری الزامی است." }, 400);

      const username = rawName.toUpperCase().startsWith("KING_") ? rawName : "KING_" + rawName;
      const protocol = body.protocol || "VLESS";
      const port = body.port || "443";
      const traffic = body.traffic ? body.traffic + " GB" : "100 GB";
      const expire = body.expire ? body.expire + " روز" : "30 روز";
      const adblock = body.adblock || "on";
      const adult_block = body.adult_block || "on";
      const status = body.status || "active";

      if (body.id) {
        await env.DB.prepare(
          "UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, adblock = ?, adult_block = ?, status = ? WHERE id = ?"
        ).bind(protocol, traffic, expire, port, adblock, adult_block, status, body.id).run();
        return jsonResponse({ success: true, message: "کاربر با موفقیت ویرایش شد." });
      } else {
        const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) return jsonResponse({ error: "این نام کاربری قبلاً ثبت شده است." }, 400);

        const id = "usr_" + Date.now();
        const uuid = generateUUID();

        await env.DB.prepare(
          "INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', ?, ?, ?)"
        ).bind(id, username, uuid, protocol, traffic, expire, port, adblock, adult_block, status).run();

        return jsonResponse({ success: true, message: "کاربر ثبت شد." });
      }
    }

    if (path.startsWith("/api/users/") && method === "DELETE") {
      const id = path.split("/")[3];
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
      return jsonResponse({ success: true });
    }

    return new Response(getMasterDashboardHtml(host), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json;charset=UTF-8" } });
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function generateUserStatusHtml(username, host) {
  return "<!DOCTYPE html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"UTF-8\"><title>وضعیت " + username + "</title><style>body{background:#030508;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.card{background:#0a0e17;border:1px solid rgba(245,158,11,0.4);padding:35px;border-radius:20px;text-align:center;width:380px;}</style></head><body><div class=\"card\"><h2 style=\"color:#f59e0b;\">" + username + "</h2><p style=\"color:#10b981;font-weight:bold;\">● اشتراک فعال و متصل (KingAmir)</p><p style=\"color:#9ca3af;font-size:12px;\">سرور اصلی: " + host + "</p></div></body></html>";
}

function getMasterDashboardHtml(host) {
  return "<!DOCTYPE html>\n" +
  "<html lang=\"fa\" dir=\"rtl\">\n" +
  "<head>\n" +
  "    <meta charset=\"UTF-8\">\n" +
  "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
  "    <title>KINGAMIR PANEL</title>\n" +
  "    <style>\n" +
  "        :root {\n" +
  "            --bg-base: #030508;\n" +
  "            --bg-card: #0a0e17;\n" +
  "            --border-color: #1e2634;\n" +
  "            --border-gold: rgba(245, 158, 11, 0.4);\n" +
  "            --gold: #f59e0b;\n" +
  "            --text-main: #f3f4f6;\n" +
  "            --text-muted: #9ca3af;\n" +
  "            --success: #10b981;\n" +
  "            --danger: #ef4444;\n" +
  "            --vless: #3b82f6;\n" +
  "            --trojan: #8b5cf6;\n" +
  "            --ss: #f97316;\n" +
  "        }\n" +
  "        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }\n" +
  "        body { background-color: var(--bg-base); color: var(--text-main); padding: 14px; min-height: 100vh; }\n" +
  "        .wrapper { max-width: 1400px; margin: 0 auto; }\n" +
  "        .header { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px 22px; border-radius: 16px; margin-bottom: 18px; }\n" +
  "        .logo-text { font-size: 22px; font-weight: 900; color: var(--gold); letter-spacing: 2px; }\n" +
  "        .server-status-pill { display: flex; align-items: center; gap: 8px; font-size: 12px; background: rgba(16, 185, 129, 0.12); color: var(--success); padding: 7px 14px; border-radius: 20px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; }\n" +
  "        .pulse-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }\n" +
  "        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }\n" +
  "        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 18px; }\n" +
  "        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px; border-radius: 14px; position: relative; overflow: hidden; }\n" +
  "        .stat-card::after { content: ''; position: absolute; top: 0; right: 0; width: 4px; height: 100%; background: var(--gold); }\n" +
  "        .stat-title { font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; text-transform: uppercase; }\n" +
  "        .stat-val { font-size: 16px; font-weight: 900; color: var(--text-main); }\n" +
  "        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 14px 18px; border-radius: 14px; gap: 12px; flex-wrap: wrap; }\n" +
  "        .search-box { flex: 1; min-width: 250px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 11px 16px; color: white; outline: none; font-size: 13px; }\n" +
  "        .search-box:focus { border-color: var(--gold); }\n" +
  "        .btn-gold { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; border: none; padding: 11px 22px; font-weight: 900; border-radius: 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; box-shadow: 0 4px 15px rgba(245, 158, 11, 0.35); }\n" +
  "        .btn-outline { background: var(--bg-base); color: var(--text-main); border: 1px solid var(--border-color); padding: 11px 18px; font-weight: 700; border-radius: 12px; cursor: pointer; font-size: 13px; }\n" +
  "        .users-list { display: flex; flex-direction: column; gap: 14px; }\n" +
  "        .user-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 18px; }\n" +
  "        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }\n" +
  "        .card-actions-left { display: flex; gap: 6px; }\n" +
  "        .icon-btn { width: 34px; height: 34px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 9px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); font-size: 14px; }\n" +
  "        .icon-btn.del:hover { background: rgba(239, 68, 68, 0.2); color: var(--danger); border-color: var(--danger); }\n" +
  "        .icon-btn.copy:hover { border-color: var(--gold); color: var(--gold); }\n" +
  "        .icon-btn.edit:hover { border-color: var(--vless); color: var(--vless); }\n" +
  "        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 4px 10px; border-radius: 7px; font-size: 11px; font-weight: bold; border: 1px solid rgba(16, 185, 129, 0.3); }\n" +
  "        .badge-disabled { background: rgba(239, 68, 68, 0.15); color: var(--danger); padding: 4px 10px; border-radius: 7px; font-size: 11px; font-weight: bold; border: 1px solid rgba(239, 68, 68, 0.3); }\n" +
  "        .username-title { font-size: 16px; font-weight: 900; color: white; }\n" +
  "        .progress-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 12px; border: 1px solid var(--border-color); }\n" +
  "        .prog-item label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-bottom: 5px; }\n" +
  "        .prog-bar { width: 100%; height: 6px; background: var(--bg-base); border-radius: 3px; overflow: hidden; border: 1px solid var(--border-color); }\n" +
  "        .prog-fill { width: 30%; height: 100%; background: var(--vless); border-radius: 3px; }\n" +
  "        .details-grid { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 12px; margin-bottom: 14px; }\n" +
  "        .proto-badge { padding: 4px 10px; border-radius: 7px; font-weight: bold; font-size: 11px; }\n" +
  "        .p-vless { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }\n" +
  "        .p-trojan { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }\n" +
  "        .p-ss { background: rgba(249, 115, 22, 0.15); color: #fb923c; }\n" +
  "        .card-bottom-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }\n" +
  "        .sub-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); padding: 10px; border-radius: 10px; font-size: 12px; font-weight: bold; text-align: center; cursor: pointer; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px; }\n" +
  "        .sub-btn.green { background: rgba(16, 185, 129, 0.1); color: var(--success); }\n" +
  "        .sub-btn.purple { background: rgba(139, 92, 246, 0.1); color: #a78bfa; grid-column: span 2; }\n" +
  "        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3,5,8,0.88); backdrop-filter: blur(10px); justify-content: center; align-items: center; padding: 15px; z-index: 2000; }\n" +
  "        .modal-content { background: var(--bg-card); border: 1px solid var(--border-gold); width: 100%; max-width: 650px; padding: 28px; border-radius: 20px; max-height: 90vh; overflow-y: auto; }\n" +
  "        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; border-bottom: 1px solid var(--border-color); padding-bottom: 14px; }\n" +
  "        .modal-title { color: var(--gold); font-size: 18px; font-weight: 900; }\n" +
  "        .close-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-muted); width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; }\n" +
  "        .form-section-title { font-size: 12px; color: var(--gold); font-weight: bold; margin: 16px 0 8px 0; border-bottom: 1px dashed var(--border-color); padding-bottom: 4px; }\n" +
  "        .form-group { margin-bottom: 14px; }\n" +
  "        .form-group.full { grid-column: span 2; }\n" +
  "        .form-row-inputs { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }\n" +
  "        label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; }\n" +
  "        input, select, textarea { width: 100%; padding: 12px 16px; background: var(--bg-base); border: 1px solid var(--border-color); color: white; border-radius: 12px; outline: none; font-size: 13px; }\n" +
  "        input:focus, select:focus, textarea:focus { border-color: var(--gold); }\n" +
  "        .toggle-row { display: flex; justify-content: space-between; align-items: center; background: var(--bg-base); padding: 12px 16px; border-radius: 12px; border: 1px solid var(--border-color); margin-bottom: 12px; }\n" +
  "        .modal-footer { display: flex; gap: 12px; margin-top: 25px; border-top: 1px solid var(--border-color); padding-top: 18px; }\n" +
  "        .ip-list-container { margin-top: 15px; max-height: 160px; overflow-y: auto; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 10px; }\n" +
  "        .ip-item-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; border-bottom: 1px solid var(--border-color); font-size: 12px; font-family: monospace; }\n" +
  "        .ip-item-row:last-child { border-bottom: none; }\n" +
  "        .del-ip-btn { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); padding: 3px 8px; border-radius: 6px; cursor: pointer; font-size: 11px; font-family: sans-serif; font-weight: bold; }\n" +
  "        .del-ip-btn:hover { background: var(--danger); color: white; }\n" +
  "    </style>\n" +
  "</head>\n" +
  "<body>\n" +
  "    <div class=\"wrapper\">\n" +
  "        <header class=\"header\">\n" +
  "            <div class=\"logo-text\">KINGAMIR PANEL</div>\n" +
  "            <div class=\"server-status-pill\">\n" +
  "                <div class=\"pulse-dot\"></div>\n" +
  "                <span id=\"active-ip-display\">در حال بارگذاری آی‌پی...</span>\n" +
  "            </div>\n" +
  "        </header>\n" +
  "        <div class=\"stats-grid\">\n" +
  "            <div class=\"stat-card\">\n" +
  "                <div class=\"stat-title\">وضعیت سرور</div>\n" +
  "                <div class=\"stat-val\" style=\"color:var(--success);\">پایداری کامل</div>\n" +
  "            </div>\n" +
  "            <div class=\"stat-card\">\n" +
  "                <div class=\"stat-title\">تعداد کل کاربران</div>\n" +
  "                <div class=\"stat-val\" id=\"stat-total\">0</div>\n" +
  "            </div>\n" +
  "        </div>\n" +
  "        <div class=\"toolbar\">\n" +
  "            <input type=\"text\" class=\"search-box\" id=\"search-input\" placeholder=\"🔍 جستجوی نام کاربری...\" onkeyup=\"filterUsers()\">\n" +
  "            <div style=\"display: flex; gap: 8px;\">\n" +
  "                <button class=\"btn-outline\" onclick=\"openCleanIpModal()\" style=\"border-color: var(--gold); color: var(--gold);\">⚡ مدیریت مخزن آی‌پی</button>\n" +
  "                <button class=\"btn-gold\" onclick=\"openModal()\">+ ایجاد کاربر جدید</button>\n" +
  "            </div>\n" +
  "        </div>\n" +
  "        <div class=\"users-list\" id=\"users-container\"></div>\n" +
  "        <div class=\"modal\" id=\"userModal\">\n" +
  "            <div class=\"modal-content\">\n" +
  "                <div class=\"modal-header\">\n" +
  "                    <div class=\"modal-title\" id=\"modal-main-title\">ایجاد اشتراک جدید</div>\n" +
  "                    <button class=\"close-btn\" onclick=\"closeModal()\">&times;</button>\n" +
  "                </div>\n" +
  "                <form id=\"user-form\">\n" +
  "                    <input type=\"hidden\" id=\"f-edit-id\">\n" +
  "                    <div class=\"form-section-title\">انتخاب پروتکل و پورت</div>\n" +
  "                    <div class=\"form-row-inputs\">\n" +
  "                        <div class=\"form-group\">\n" +
  "                            <label>پروتکل</label>\n" +
  "                            <select id=\"f-protocol\">\n" +
  "                                <option value=\"VLESS\">VLESS</option>\n" +
  "                                <option value=\"Trojan\">Trojan</option>\n" +
  "                                <option value=\"Shadowsocks\">Shadowsocks</option>\n" +
  "                            </select>\n" +
  "                        </div>\n" +
  "                        <div class=\"form-group\">\n" +
  "                            <label>پورت اتصال</label>\n" +
  "                            <select id=\"f-port\">\n" +
  "                                <option value=\"443\">443 (پیش‌فرض)</option>\n" +
  "                                <option value=\"2053\">2053</option>\n" +
  "                                <option value=\"2083\">2083</option>\n" +
  "                                <option value=\"2087\">2087</option>\n" +
  "                                <option value=\"8443\">8443</option>\n" +
  "                            </select>\n" +
  "                        </div>\n" +
  "                    </div>\n" +
  "                    <div class=\"form-section-title\">مشخصات کاربری</div>\n" +
  "                    <div class=\"form-group full\">\n" +
  "                        <label>نام کاربری (پیش‌وند KING_ خودکار اضافه می‌شود)</label>\n" +
  "                        <input type=\"text\" id=\"f-username\" required placeholder=\"مثال: ali یا user1\">\n" +
  "                    </div>\n" +
  "                    <div class=\"form-section-title\">حجم و زمان انقضا</div>\n" +
  "                    <div class=\"form-row-inputs\">\n" +
  "                        <div class=\"form-group\">\n" +
  "                            <label>حجم (GB)</label>\n" +
  "                            <input type=\"number\" id=\"f-traffic\" value=\"100\" required>\n" +
  "                        </div>\n" +
  "                        <div class=\"form-group\">\n" +
  "                            <label>مدت زمان (روز)</label>\n" +
  "                            <input type=\"number\" id=\"f-expire\" value=\"30\" required>\n" +
  "                        </div>\n" +
  "                    </div>\n" +
  "                    <div class=\"form-section-title\">تنظیمات امنیتی و وضعیت</div>\n" +
  "                    <div class=\"form-group\">\n" +
  "                        <label>وضعیت حساب</label>\n" +
  "                        <select id=\"f-status\">\n" +
  "                            <option value=\"active\">فعال</option>\n" +
  "                            <option value=\"disabled\">غیرفعال</option>\n" +
  "                        </select>\n" +
  "                    </div>\n" +
  "                    <div class=\"toggle-row\">\n" +
  "                        <span style=\"font-size: 12px; font-weight: 700;\">مسدودسازی تبلیغات (AdBlock)</span>\n" +
  "                        <input type=\"checkbox\" id=\"f-adblock\" checked style=\"width: 18px; height: 18px; accent-color: var(--gold);\">\n" +
  "                    </div>\n" +
  "                    <div class=\"toggle-row\">\n" +
  "                        <span style=\"font-size: 12px; font-weight: 700;\">مسدودسازی سایت‌های +18</span>\n" +
  "                        <input type=\"checkbox\" id=\"f-adult\" checked style=\"width: 18px; height: 18px; accent-color: var(--gold);\">\n" +
  "                    </div>\n" +
  "                    <div class=\"modal-footer\">\n" +
  "                        <button type=\"button\" class=\"btn-outline\" onclick=\"closeModal()\" style=\"flex: 1;\">انصراف</button>\n" +
  "                        <button type=\"submit\" class=\"btn-gold\" style=\"flex: 2; justify-content: center;\">ذخیره در دیتابیس</button>\n" +
  "                    </div>\n" +
  "                </form>\n" +
  "            </div>\n" +
  "        </div>\n" +
  "        <div class=\"modal\" id=\"cleanIpModal\">\n" +
  "            <div class=\"modal-content\">\n" +
  "                <div class=\"modal-header\">\n" +
  "                    <div class=\"modal-title\">⚡ ثبت و مدیریت مخزن آی‌پی تمیز</div>\n" +
  "                    <button class=\"close-btn\" onclick=\"closeCleanIpModal()\">&times;</button>\n" +
  "                </div>\n" +
  "                <div>\n" +
  "                    <label>وارد کردن آی‌پی تمیز جدید:</label>\n" +
  "                    <div style=\"display: flex; gap: 8px; margin-top: 8px;\">\n" +
  "                        <input type=\"text\" id=\"ip-input-field\" placeholder=\"مثال: 104.16.132.229\" style=\"font-family: monospace; flex: 1;\">\n" +
  "                        <button type=\"button\" class=\"btn-gold\" onclick=\"saveCleanIpDirect()\">اعمال و ذخیره</button>\n" +
  "                    </div>\n" +
  "                    <div class=\"form-section-title\" style=\"margin-top: 20px;\">مخزن آی‌پی‌های ذخیره‌شده (قابل حذف)</div>\n" +
  "                    <div class=\"ip-list-container\" id=\"saved-ips-list\">\n" +
  "                        <div style=\"text-align:center; color:var(--text-muted); padding:15px;\">در حال بارگذاری مخزن...</div>\n" +
  "                    </div>\n" +
  "                    <div class=\"modal-footer\">\n" +
  "                        <button type=\"button\" class=\"btn-outline\" onclick=\"closeCleanIpModal()\" style=\"width: 100%;\">بستن پنجره</button>\n" +
  "                    </div>\n" +
  "                </div>\n" +
  "            </div>\n" +
  "        </div>\n" +
  "    </div>\n" +
  "    <script>\n" +
  "        let allUsersCache = [];\n" +
  "        let savedIpsCache = [];\n" +
  "        const currentHost = \"" + host + "\";\n" +
  "        async function loadUsers() {\n" +
  "            try {\n" +
  "                const res = await fetch('/api/users');\n" +
  "                const data = await res.json();\n" +
  "                if(data.success) {\n" +
  "                    allUsersCache = data.users;\n" +
  "                    savedIpsCache = data.savedIps || [];\n" +
  "                    document.getElementById('stat-total').innerText = data.metrics.total;\n" +
  "                    document.getElementById('active-ip-display').innerText = 'آی‌پی فعال: ' + data.activeCleanIp;\n" +
  "                    renderUsers(allUsersCache);\n" +
  "                    renderSavedIps();\n" +
  "                }\n" +
  "            } catch(e) { console.error(e); }\n" +
  "        }\n" +
  "        function renderUsers(list) {\n" +
  "            const container = document.getElementById('users-container');\n" +
  "            container.innerHTML = '';\n" +
  "            if(list.length === 0) {\n" +
  "                container.innerHTML = '<div style=\"text-align:center; color:var(--text-muted); padding:50px;\">هیچ کاربری ثبت نشده است.</div>';\n" +
  "                return;\n" +
  "            }\n" +
  "            list.forEach(u => {\n" +
  "                let pClass = 'p-vless';\n" +
  "                if(u.protocol === 'Trojan') pClass = 'p-trojan';\n" +
  "                if(u.protocol === 'Shadowsocks') pClass = 'p-ss';\n" +
  "                const userPort = u.port || '443';\n" +
  "                const isAct = u.status !== 'disabled';\n" +
  "                const badgeHtml = isAct ? '<span class=\"badge-active\">● فعال</span>' : '<span class=\"badge-disabled\">● غیرفعال</span>';\n" +
  "                const subUrl = 'https://' + currentHost + '/sub/' + u.username;\n" +
  "                const yamlUrl = 'https://' + currentHost + '/yaml/' + u.username;\n" +
  "                const statusUrl = 'https://' + currentHost + '/status/' + u.username;\n" +
  "                container.innerHTML += '<div class=\"user-card\">' +\n" +
  "                    '<div class=\"card-top\">' +\n" +
  "                        '<div class=\"card-actions-left\">' +\n" +
  "                            '<div class=\"icon-btn del\" onclick=\"deleteUser(\\'' + u.id + '\\')\" title=\"حذف\">🗑️</div>' +\n" +
  "                            '<div class=\"icon-btn edit\" onclick=\"openEditModal(\\'' + u.id + '\\')\" title=\"ویرایش\">✏️</div>' +\n" +
  "                            '<div class=\"icon-btn copy\" onclick=\"copyText(\\'' + subUrl + '\\')\" title=\"کپی ساب\">📋</div>' +\n" +
  "                        '</div>' +\n" +
  "                        '<div style=\"display:flex; align-items:center; gap:8px;\">' +\n" +
  "                            badgeHtml +\n" +
  "                            '<span class=\"username-title\">' + u.username + '</span>' +\n" +
  "                        '</div>' +\n" +
  "                    '</div>' +\n" +
  "                    '<div class=\"progress-grid\">' +\n" +
  "                        '<div class=\"prog-item\">' +\n" +
  "                            '<label><span>حجم</span> <span style=\"color:white;\">' + u.traffic + '</span></label>' +\n" +
  "                            '<div class=\"prog-bar\"><div class=\"prog-fill\"></div></div>' +\n" +
  "                        '</div>' +\n" +
  "                        '<div class=\"prog-item\">' +\n" +
  "                            '<label><span>زمان</span> <span style=\"color:white;\">' + u.expire + '</span></label>' +\n" +
  "                            '<div class=\"prog-bar\"><div class=\"prog-fill\" style=\"background:var(--gold);\"></div></div>' +\n" +
  "                        '</div>' +\n" +
  "                    '</div>' +\n" +
  "                    '<div class=\"details-grid\">' +\n" +
  "                        '<div>پورت: <span style=\"color:white; font-family:monospace;\">' + userPort + '</span></div>' +\n" +
  "                        '<div>پروتکل: <span class=\"proto-badge ' + pClass + '\">' + u.protocol + '</span></div>' +\n" +
  "                    '</div>' +\n" +
  "                    '<div class=\"card-bottom-btns\">' +\n" +
  "                        '<a href=\"' + statusUrl + '\" target=\"_blank\" class=\"sub-btn green\">🔗 صفحه وضعیت</a>' +\n" +
  "                        '<a href=\"' + subUrl + '\" target=\"_blank\" class=\"sub-btn\">📄 ساب متنی</a>' +\n" +
  "                        '<a href=\"' + yamlUrl + '\" target=\"_blank\" class=\"sub-btn purple\">⚡ ساب YAML</a>' +\n" +
  "                    '</div>' +\n" +
  "                '</div>';\n" +
  "            });\n" +
  "        }\n" +
  "        function renderSavedIps() {\n" +
  "            const container = document.getElementById('saved-ips-list');\n" +
  "            container.innerHTML = '';\n" +
  "            if(savedIpsCache.length === 0) {\n" +
  "                container.innerHTML = '<div style=\"text-align:center; color:var(--text-muted); padding:15px;\">هیچ آی‌پی در مخزن ذخیره نشده است.</div>';\n" +
  "                return;\n" +
  "            }\n" +
  "            savedIpsCache.forEach(item => {\n" +
  "                container.innerHTML += '<div class=\"ip-item-row\">' +\n" +
  "                    '<span>' + item.ip + '</span>' +\n" +
  "                    '<button class=\"del-ip-btn\" onclick=\"deleteSavedIp(\\'' + item.id + '\\')\">حذف</button>' +\n" +
  "                '</div>';\n" +
  "            });\n" +
  "        }\n" +
  "        function copyText(txt) {\n" +
  "            navigator.clipboard.writeText(txt);\n" +
  "            alert('لینک ساب با موفقیت کپی شد!');\n" +
  "        }\n" +
  "        function filterUsers() {\n" +
  "            const query = document.getElementById('search-input').value.toLowerCase();\n" +
  "            renderUsers(allUsersCache.filter(u => u.username.toLowerCase().includes(query)));\n" +
  "        }\n" +
  "        function openModal() {\n" +
  "            document.getElementById('modal-main-title').innerText = 'ایجاد اشتراک جدید';\n" +
  "            document.getElementById('f-edit-id').value = '';\n" +
  "            document.getElementById('f-username').disabled = false;\n" +
  "            document.getElementById('user-form').reset();\n" +
  "            document.getElementById('userModal').style.display = 'flex';\n" +
  "        }\n" +
  "        function openEditModal(id) {\n" +
  "            const u = allUsersCache.find(x => x.id === id);\n" +
  "            if(!u) return;\n" +
  "            document.getElementById('modal-main-title').innerText = 'ویرایش اشتراک: ' + u.username;\n" +
  "            document.getElementById('f-edit-id').value = u.id;\n" +
  "            document.getElementById('f-username').value = u.username;\n" +
  "            document.getElementById('f-username').disabled = true;\n" +
  "            document.getElementById('f-protocol').value = u.protocol || 'VLESS';\n" +
  "            document.getElementById('f-port').value = u.port || '443';\n" +
  "            document.getElementById('f-traffic').value = parseInt(u.traffic) || 100;\n" +
  "            document.getElementById('f-expire').value = parseInt(u.expire) || 30;\n" +
  "            document.getElementById('f-status').value = u.status || 'active';\n" +
  "            document.getElementById('f-adblock').checked = u.adblock === 'on';\n" +
  "            document.getElementById('f-adult').checked = u.adult_block === 'on';\n" +
  "            document.getElementById('userModal').style.display = 'flex';\n" +
  "        }\n" +
  "        function closeModal() { document.getElementById('userModal').style.display = 'none'; }\n" +
  "        function openCleanIpModal() {\n" +
  "            document.getElementById('cleanIpModal').style.display = 'flex';\n" +
  "            loadUsers();\n" +
  "        }\n" +
  "        function closeCleanIpModal() {\n" +
  "            document.getElementById('cleanIpModal').style.display = 'none';\n" +
  "        }\n" +
  "        async function saveCleanIpDirect() {\n" +
  "            const ip = document.getElementById('ip-input-field').value.trim();\n" +
  "            if(!ip) { alert('لطفاً یک آی‌پی معتبر وارد کنید.'); return; }\n" +
  "            const res = await fetch('/api/set-clean-ip', {\n" +
  "                method: 'POST',\n" +
  "                headers: { 'Content-Type': 'application/json' },\n" +
  "                body: JSON.stringify({ ip: ip })\n" +
  "            });\n" +
  "            const data = await res.json();\n" +
  "            if(data.success) {\n" +
  "                document.getElementById('ip-input-field').value = '';\n" +
  "                alert('آی‌پی با موفقیت ثبت و اعمال شد!');\n" +
  "                loadUsers();\n" +
  "            } else { alert('خطا در ثبت آی‌پی'); }\n" +
  "        }\n" +
  "        async function deleteSavedIp(ipKey) {\n" +
  "            if(!confirm('آیا از حذف این آی‌پی از مخزن مطمئن هستید؟')) return;\n" +
  "            const res = await fetch('/api/delete-ip/' + ipKey, { method: 'DELETE' });\n" +
  "            const data = await res.json();\n" +
  "            if(data.success) { loadUsers(); }\n" +
  "        }\n" +
  "        document.getElementById('user-form').addEventListener('submit', async (e) => {\n" +
  "            e.preventDefault();\n" +
  "            const editId = document.getElementById('f-edit-id').value;\n" +
  "            const payload = {\n" +
  "                id: editId ? editId : undefined,\n" +
  "                username: document.getElementById('f-username').value,\n" +
  "                protocol: document.getElementById('f-protocol').value,\n" +
  "                port: document.getElementById('f-port').value,\n" +
  "                traffic: document.getElementById('f-traffic').value,\n" +
  "                expire: document.getElementById('f-expire').value,\n" +
  "                status: document.getElementById('f-status').value,\n" +
  "                adblock: document.getElementById('f-adblock').checked ? 'on' : 'off',\n" +
  "                adult_block: document.getElementById('f-adult').checked ? 'on' : 'off'\n" +
  "            };\n" +
  "            const res = await fetch('/api/users', {\n" +
  "                method: 'POST',\n" +
  "                headers: { 'Content-Type': 'application/json' },\n" +
  "                body: JSON.stringify(payload)\n" +
  "            });\n" +
  "            const data = await res.json();\n" +
  "            if(data.success) {\n" +
  "                closeModal();\n" +
  "                loadUsers();\n" +
  "            } else { alert(data.error || 'خطا در ذخیره اطلاعات'); }\n" +
  "        });\n" +
  "        async function deleteUser(id) {\n" +
  "            if(!confirm('آیا از حذف این کاربر مطمئن هستید؟')) return;\n" +
  "            const res = await fetch('/api/users/' + id, { method: 'DELETE' });\n" +
  "            const data = await res.json();\n" +
  "            if(data.success) loadUsers();\n" +
  "        }\n" +
  "        loadUsers();\n" +
  "    </script>\n" +
  "</body>\n" +
  "</html>";
}
