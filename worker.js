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
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT, uuid TEXT, protocol TEXT, traffic TEXT, expire TEXT, port TEXT, tls TEXT, adblock TEXT, adult_block TEXT, status TEXT)`).run();
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
      const encodedName = encodeURIComponent(user.username);

      const vlessLink = "vless://" + uUuid + "@" + activeCleanIp + ":" + uPort + "?encryption=none&security=tls&sni=" + host + "&fp=chrome&type=ws&host=" + host + "&path=%2F%3Fed%3D2048#" + encodedName + "-VLESS";
      const trojanLink = "trojan://" + uUuid + "@" + activeCleanIp + ":" + uPort + "?security=tls&sni=" + host + "&type=ws&host=" + host + "&path=%2F%3Fed%3D2048#" + encodedName + "-Trojan";
      const auth = btoa("chacha20-ietf-poly1305:" + uUuid);
      const ssLink = "ss://" + auth + "@" + activeCleanIp + ":" + uPort + "#" + encodedName + "-SS";

      const allConfigs = vlessLink + "\n" + trojanLink + "\n" + ssLink;
      const encodedBase64 = btoa(String.fromCharCode(...new TextEncoder().encode(allConfigs)));

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
      const yamlContent = `proxies:
  - name: "${user.username}-VLESS"
    type: vless
    server: ${activeCleanIp}
    port: ${uPort}
    uuid: ${uUuid}
    network: ws
    tls: true
    sni: ${host}
    skip-cert-verify: true
    client-fingerprint: chrome
    ws-opts:
      path: "/?ed=2048"
      headers:
        Host: ${host}`;

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

      const username = rawName.toUpperCase().startsWith("KINGAMIR_") ? rawName : "KINGAMIR_" + rawName;
      const protocol = body.protocol || "VLESS";
      const port = body.port || "443";
      const traffic = body.traffic ? body.traffic + " GB" : "100 GB";
      const expire = body.expire ? body.expire + " روز" : "30 روز";
      const adblock = body.adblock || "on";
      const adult_block = body.adult_block || "on";

      const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
      if (existing) return jsonResponse({ error: "این نام کاربری قبلاً ثبت شده است." }, 400);

      const id = "usr_" + Date.now();
      const uuid = generateUUID();

      await env.DB.prepare(
        "INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'TLS 1.3', ?, ?, 'active')"
      ).bind(id, username, uuid, protocol, traffic, expire, port, adblock, adult_block).run();

      return jsonResponse({ success: true, message: "کاربر ثبت شد." });
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
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>وضعیت ${username}</title><style>body{background:#030508;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.card{background:#0a0e17;border:1px solid rgba(245,158,11,0.4);padding:35px;border-radius:20px;text-align:center;width:380px;}</style></head><body><div class="card"><h2 style="color:#f59e0b;">${username}</h2><p style="color:#10b981;font-weight:bold;">● اشتراک فعال و متصل (KingAmir)</p><p style="color:#9ca3af;font-size:12px;">سرور اصلی: ${host}</p></div></body></html>`;
}

function getMasterDashboardHtml(host) {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KINGAMIR PANEL</title>
    <style>
        :root {
            --bg-base: #030508;
            --bg-card: #0a0e17;
            --border-color: #1e2634;
            --border-gold: rgba(245, 158, 11, 0.4);
            --gold: #f59e0b;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --danger: #ef4444;
            --vless: #3b82f6;
            --trojan: #8b5cf6;
            --ss: #f97316;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
        body { background-color: var(--bg-base); color: var(--text-main); padding: 14px; min-height: 100vh; }
        .wrapper { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px 22px; border-radius: 16px; margin-bottom: 18px; }
        .logo-text { font-size: 22px; font-weight: 900; color: var(--gold); letter-spacing: 2px; }
        .server-status-pill { display: flex; align-items: center; gap: 8px; font-size: 12px; background: rgba(16, 185, 129, 0.12); color: var(--success); padding: 7px 14px; border-radius: 20px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; }
        .pulse-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 18px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px; border-radius: 14px; position: relative; overflow: hidden; }
        .stat-card::after { content: ''; position: absolute; top: 0; right: 0; width: 4px; height: 100%; background: var(--gold); }
        .stat-title { font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; text-transform: uppercase; }
        .stat-val { font-size: 16px; font-weight: 900; color: var(--text-main); }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 14px 18px; border-radius: 14px; gap: 12px; flex-wrap: wrap; }
        .search-box { flex: 1; min-width: 250px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 11px 16px; color: white; outline: none; font-size: 13px; }
        .search-box:focus { border-color: var(--gold); }
        .btn-gold { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; border: none; padding: 11px 22px; font-weight: 900; border-radius: 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; box-shadow: 0 4px 15px rgba(245, 158, 11, 0.35); }
        .btn-outline { background: var(--bg-base); color: var(--text-main); border: 1px solid var(--border-color); padding: 11px 18px; font-weight: 700; border-radius: 12px; cursor: pointer; font-size: 13px; }
        .users-list { display: flex; flex-direction: column; gap: 14px; }
        .user-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 18px; }
        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
        .card-actions-left { display: flex; gap: 6px; }
        .icon-btn { width: 34px; height: 34px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 9px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); font-size: 14px; }
        .icon-btn.del:hover { background: rgba(239, 68, 68, 0.2); color: var(--danger); border-color: var(--danger); }
        .icon-btn.copy:hover { border-color: var(--gold); color: var(--gold); }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 4px 10px; border-radius: 7px; font-size: 11px; font-weight: bold; border: 1px solid rgba(16, 185, 129, 0.3); }
        .username-title { font-size: 16px; font-weight: 900; color: white; }
        .progress-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 12px; border: 1px solid var(--border-color); }
        .prog-item label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-bottom: 5px; }
        .prog-bar { width: 100%; height: 6px; background: var(--bg-base); border-radius: 3px; overflow: hidden; border: 1px solid var(--border-color); }
        .prog-fill { width: 30%; height: 100%; background: var(--vless); border-radius: 3px; }
        .details-grid { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 12px; margin-bottom: 14px; }
        .proto-badge { padding: 4px 10px; border-radius: 7px; font-weight: bold; font-size: 11px; }
        .p-vless { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .p-trojan { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }
        .p-ss { background: rgba(249, 115, 22, 0.15); color: #fb923c; }
        .card-bottom-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .sub-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); padding: 10px; border-radius: 10px; font-size: 12px; font-weight: bold; text-align: center; cursor: pointer; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px; }
        .sub-btn.green { background: rgba(16, 185, 129, 0.1); color: var(--success); }
        .sub-btn.purple { background: rgba(139, 92, 246, 0.1); color: #a78bfa; grid-column: span 2; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3,5,8,0.88); backdrop-filter: blur(10px); justify-content: center; align-items: center; padding: 15px; z-index: 2000; }
        .modal-content { background: var(--bg-card); border: 1px solid var(--border-gold); width: 100%; max-width: 650px; padding: 28px; border-radius: 20px; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; border-bottom: 1px solid var(--border-color); padding-bottom: 14px; }
        .modal-title { color: var(--gold); font-size: 18px; font-weight: 900; }
        .close-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-muted); width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; }
        .form-section-title { font-size: 12px; color: var(--gold); font-weight: bold; margin: 16px 0 8px 0; border-bottom: 1px dashed var(--border-color); padding-bottom: 4px; }
        .form-group { margin-bottom: 14px; }
        .form-group.full { grid-column: span 2; }
        .form-row-inputs { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; }
        input, select, textarea { width: 100%; padding: 12px 16px; background: var(--bg-base); border: 1px solid var(--border-color); color: white; border-radius: 12px; outline: none; font-size: 13px; }
        input:focus, select:focus, textarea:focus { border-color: var(--gold); }
        .toggle-row { display: flex; justify-content: space-between; align-items: center; background: var(--bg-base); padding: 12px 16px; border-radius: 12px; border: 1px solid var(--border-color); margin-bottom: 12px; }
        .modal-footer { display: flex; gap: 12px; margin-top: 25px; border-top: 1px solid var(--border-color); padding-top: 18px; }
        .ip-list-container { margin-top: 15px; max-height: 160px; overflow-y: auto; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 10px; }
        .ip-item-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; border-bottom: 1px solid var(--border-color); font-size: 12px; font-family: monospace; }
        .ip-item-row:last-child { border-bottom: none; }
        .del-ip-btn { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); padding: 3px 8px; border-radius: 6px; cursor: pointer; font-size: 11px; font-family: sans-serif; font-weight: bold; }
        .del-ip-btn:hover { background: var(--danger); color: white; }
    </style>
</head>
<body>

    <div class="wrapper">
        <header class="header">
            <div class="logo-text">KINGAMIR PANEL</div>
            <div class="server-status-pill">
                <div class="pulse-dot"></div>
                <span id="active-ip-display">در حال بارگذاری آی‌پی...</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">وضعیت سرور</div>
                <div class="stat-val" style="color:var(--success);">پایداری کامل</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">تعداد کل کاربران</div>
                <div class="stat-val" id="stat-total">0</div>
            </div>
        </div>

        <div class="toolbar">
            <input type="text" class="search-box" id="search-input" placeholder="🔍 جستجوی نام کاربری..." onkeyup="filterUsers()">
            <div style="display: flex; gap: 8px;">
                <button class="btn-outline" onclick="openCleanIpModal()" style="border-color: var(--gold); color: var(--gold);">⚡ مدیریت مخزن آی‌پی</button>
                <button class="btn-gold" onclick="openModal()">+ ایجاد کاربر جدید</button>
            </div>
        </div>

        <div class="users-list" id="users-container"></div>

        <!-- مدال ایجاد کاربر -->
        <div class="modal" id="userModal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">ایجاد اشتراک جدید</div>
                    <button class="close-btn" onclick="closeModal()">&times;</button>
                </div>
                <form id="user-form">
                    <div class="form-section-title">انتخاب پروتکل و پورت</div>
                    <div class="form-row-inputs">
                        <div class="form-group">
                            <label>پروتکل</label>
                            <select id="f-protocol">
                                <option value="VLESS">VLESS</option>
                                <option value="Trojan">Trojan</option>
                                <option value="Shadowsocks">Shadowsocks</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>پورت اتصال</label>
                            <select id="f-port">
                                <option value="443">443 (پیش‌فرض)</option>
                                <option value="2053">2053</option>
                                <option value="2083">2083</option>
                                <option value="2087">2087</option>
                                <option value="8443">8443</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-section-title">مشخصات کاربری</div>
                    <div class="form-group full">
                        <label>نام کاربری (پیش‌وند KINGAMIR_ خودکار اضافه می‌شود)</label>
                        <input type="text" id="f-username" required placeholder="مثال: ali یا user1">
                    </div>

                    <div class="form-section-title">حجم و زمان انقضا</div>
                    <div class="form-row-inputs">
                        <div class="form-group">
                            <label>حجم (GB)</label>
                            <input type="number" id="f-traffic" value="100" required>
                        </div>
                        <div class="form-group">
                            <label>مدت زمان (روز)</label>
                            <input type="number" id="f-expire" value="30" required>
                        </div>
                    </div>

                    <div class="form-section-title">تنظیمات امنیتی و مسدودسازی</div>
                    <div class="toggle-row">
                        <span style="font-size: 12px; font-weight: 700;">مسدودسازی تبلیغات (AdBlock)</span>
                        <input type="checkbox" id="f-adblock" checked style="width: 18px; height: 18px; accent-color: var(--gold);">
                    </div>
                    <div class="toggle-row">
                        <span style="font-size: 12px; font-weight: 700;">مسدودسازی سایت‌های +18</span>
                        <input type="checkbox" id="f-adult" checked style="width: 18px; height: 18px; accent-color: var(--gold);">
                    </div>

                    <div class="modal-footer">
                        <button type="button" class="btn-outline" onclick="closeModal()" style="flex: 1;">انصراف</button>
                        <button type="submit" class="btn-gold" style="flex: 2; justify-content: center;">ثبت در دیتابیس</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- مدال مدیریت مخزن آی‌پی -->
        <div class="modal" id="cleanIpModal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">⚡ ثبت و مدیریت مخزن آی‌پی تمیز</div>
                    <button class="close-btn" onclick="closeCleanIpModal()">&times;</button>
                </div>
                <div>
                    <label>وارد کردن آی‌پی تمیز جدید:</label>
                    <div style="display: flex; gap: 8px; margin-top: 8px;">
                        <input type="text" id="ip-input-field" placeholder="مثال: 104.16.132.229" style="font-family: monospace; flex: 1;">
                        <button type="button" class="btn-gold" onclick="saveCleanIpDirect()">اعمال و ذخیره</button>
                    </div>

                    <div class="form-section-title" style="margin-top: 20px;">مخزن آی‌پی‌های ذخیره‌شده (قابل حذف)</div>
                    <div class="ip-list-container" id="saved-ips-list">
                        <div style="text-align:center; color:var(--text-muted); padding:15px;">در حال بارگذاری مخزن...</div>
                    </div>
                    
                    <div class="modal-footer">
                        <button type="button" class="btn-outline" onclick="closeCleanIpModal()" style="width: 100%;">بستن پنجره</button>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
        let allUsersCache = [];
        let savedIpsCache = [];
        const currentHost = "${host}";

        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const data = await res.json();
                if(data.success) {
                    allUsersCache = data.users;
                    savedIpsCache = data.savedIps || [];
                    document.getElementById('stat-total').innerText = data.metrics.total;
                    document.getElementById('active-ip-display').innerText = 'آی‌پی فعال: ' + data.activeCleanIp;
                    renderUsers(allUsersCache);
                    renderSavedIps();
                }
            } catch(e) { console.error(e); }
        }

        function renderUsers(list) {
            const container = document.getElementById('users-container');
            container.innerHTML = '';

            if(list.length === 0) {
                container.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:50px;">هیچ کاربری ثبت نشده است.</div>';
                return;
            }

            list.forEach(u => {
                let pClass = 'p-vless';
                if(u.protocol === 'Trojan') pClass = 'p-trojan';
                if(u.protocol === 'Shadowsocks') pClass = 'p-ss';
                const userPort = u.port || '443';

                const subUrl = 'https://' + currentHost + '/sub/' + u.username;
                const yamlUrl = 'https://' + currentHost + '/yaml/' + u.username;
                const statusUrl = 'https://' + currentHost + '/status/' + u.username;

                container.innerHTML += '<div class="user-card">' +
                    '<div class="card-top">' +
                        '<div class="card-actions-left">' +
                            '<div class="icon-btn del" onclick="deleteUser(\\'' + u.id + '\\')" title="حذف">🗑️</div>' +
                            '<div class="icon-btn copy" onclick="copyText(\\'' + subUrl + '\\')" title="کپی ساب">📋</div>' +
                        '</div>' +
                        '<div style="display:flex; align-items:center; gap:8px;">' +
                            '<span class="badge-active">● فعال</span>' +
                            '<span class="username-title">' + u.username + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="progress-grid">' +
                        '<div class="prog-item">' +
                            '<label><span>حجم</span> <span style="color:white;">' + u.traffic + '</span></label>' +
                            '<div class="prog-bar"><div class="prog-fill"></div></div>' +
                        '</div>' +
                        '<div class="prog-item">' +
                            '<label><span>زمان</span> <span style="color:white;">' + u.expire + '</span></label>' +
                            '<div class="prog-bar"><div class="prog-fill" style="background:var(--gold);"></div></div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="details-grid">' +
                        '<div>پورت: <span style="color:white; font-family:monospace;">' + userPort + '</span></div>' +
                        '<div>پروتکل: <span class="proto-badge ' + pClass + '">' + u.protocol + '</span></div>' +
                    '</div>' +
                    '<div class="card-bottom-btns">' +
                        '<a href="' + statusUrl + '" target="_blank" class="sub-btn green">🔗 صفحه وضعیت</a>' +
                        '<a href="' + subUrl + '" target="_blank" class="sub-btn">📄 ساب متنی</a>' +
                        '<a href="' + yamlUrl + '" target="_blank" class="sub-btn purple">⚡ ساب YAML</a>' +
                    '</div>' +
                '</div>';
            });
        }

        function renderSavedIps() {
            const container = document.getElementById('saved-ips-list');
            container.innerHTML = '';

            if(savedIpsCache.length === 0) {
                container.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:15px;">هیچ آی‌پی در مخزن ذخیره نشده است.</div>';
                return;
            }

            savedIpsCache.forEach(item => {
                container.innerHTML += '<div class="ip-item-row">' +
                    '<span>' + item.ip + '</span>' +
                    '<button class="del-ip-btn" onclick="deleteSavedIp(\\'' + item.id + '\\')">حذف</button>' +
                '</div>';
            });
        }

        function copyText(txt) {
            navigator.clipboard.writeText(txt);
            alert('لینک ساب با موفقیت کپی شد!');
        }

        function filterUsers() {
            const query = document.getElementById('search-input').value.toLowerCase();
            renderUsers(allUsersCache.filter(u => u.username.toLowerCase().includes(query)));
        }

        function openModal() {
            document.getElementById('userModal').style.display = 'flex';
            document.getElementById('user-form').reset();
        }

        function closeModal() { 
            document.getElementById('userModal').style.display = 'none'; 
        }

        function openCleanIpModal() {
            document.getElementById('cleanIpModal').style.display = 'flex';
            loadUsers();
        }

        function closeCleanIpModal() {
            document.getElementById('cleanIpModal').style.display = 'none';
        }

        async function saveCleanIpDirect() {
            const ip = document.getElementById('ip-input-field').value.trim();
            if(!ip) {
                alert('لطفاً یک آی‌پی معتبر وارد کنید.');
                return;
            }

            const res = await fetch('/api/set-clean-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            const data = await res.json();
            if(data.success) {
                document.getElementById('ip-input-field').value = '';
                alert('آی‌پی با موفقیت ثبت و اعمال شد!');
                loadUsers();
            } else {
                alert('خطا در ثبت آی‌پی');
            }
        }

        async function deleteSavedIp(ipKey) {
            if(!confirm('آیا از حذف این آی‌پی از مخزن مطمئن هستید؟')) return;
            const res = await fetch('/api/delete-ip/' + ipKey, { method: 'DELETE' });
            const data = await res.json();
            if(data.success) {
                loadUsers();
            }
        }

        document.getElementById('user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = {
                username: document.getElementById('f-username').value,
                protocol: document.getElementById('f-protocol').value,
                port: document.getElementById('f-port').value,
                traffic: document.getElementById('f-traffic').value,
                expire: document.getElementById('f-expire').value,
                adblock: document.getElementById('f-adblock').checked ? 'on' : 'off',
                adult_block: document.getElementById('f-adult').checked ? 'on' : 'off'
            };

            const res = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            
            if(data.success) {
                closeModal();
                loadUsers();
            } else {
                alert(data.error || 'خطا در ثبت کاربر');
            }
        });

        async function deleteUser(id) {
            if(!confirm('آیا از حذف این کاربر مطمئن هستید؟')) return;
            const res = await fetch('/api/users/' + id, { method: 'DELETE' });
            const data = await res.json();
            if(data.success) loadUsers();
        }

        loadUsers();
    </script>
</body>
</html>`;
}
