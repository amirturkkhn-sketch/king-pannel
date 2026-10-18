let usersCache = [];
let ipsCache = [];

async function api(path, options={}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "خطای درخواست");
  return data;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" })[c]);
}

function toggleBody(id) {
  document.getElementById(id).classList.toggle("show");
}

async function saveEchSettings(isToggleOnly = false) {
  const enabled = document.getElementById("ech-toggle").checked;
  const value = document.getElementById("ech-value-input").value.trim();
  try {
    const res = await api("/api/set-ech", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ enabled, value }) });
    if (!isToggleOnly) alert(res.message);
  } catch(e) { alert("خطا: " + e.message); }
}

async function saveFragmentSettings(isToggleOnly = false) {
  const enabled = document.getElementById("frag-toggle").checked;
  const length = document.getElementById("frag-len-input").value.trim();
  const interval = document.getElementById("frag-int-input").value.trim();
  try {
    const res = await api("/api/set-fragment", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ enabled, length, interval }) });
    if (!isToggleOnly) alert(res.message);
  } catch(e) { alert("خطا: " + e.message); }
}

async function loadAll() {
  try {
    const data = await api("/api/users");
    usersCache = data.users || [];
    ipsCache = data.savedIps || [];
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
  } catch(e) { alert("خطا در دریافت اطلاعات: " + e.message); }
}

function filterUsers() {
  const search = document.getElementById("search-input").value.toLowerCase();
  const statusFilter = document.getElementById("filter-status").value;
  const filtered = usersCache.filter(u => u.username.toLowerCase().includes(search) && (statusFilter === "all" || u.status === statusFilter));
  renderUsersList(filtered);
}

function renderUsersList(list) {
  const root = document.getElementById("users");
  if (!list.length) { root.innerHTML = '<div class="card">کاربری یافت نشد.</div>'; return; }
  root.innerHTML = list.map(u => {
    const subUrl = window.publicPanelUrl + "/sub/" + encodeURIComponent(u.username);
    const yamlUrl = window.publicPanelUrl + "/yaml/" + encodeURIComponent(u.username);
    return `<article class="user">
      <div class="row"><h2>${esc(u.username)}</h2><span style="color:${u.status==='disabled'?'var(--red)':'var(--green)'}">${u.status==='disabled'?'غیرفعال':'فعال'}</span></div>
      <p class="muted">پروتکل: ${esc(u.protocol)} | پورت: ${esc(u.port)} | حجم: ${esc(u.traffic)}</p>
      <div style="margin-top:10px;display:flex;gap:5px;flex-wrap:wrap">
        <button class="gold" onclick="navigator.clipboard.writeText('${subUrl}').then(()=>alert('کپی شد!'))">📋 کپی ساب</button>
        <button class="outline" onclick="navigator.clipboard.writeText('${yamlUrl}').then(()=>alert('YAML کپی شد!'))">📄 کپی YAML</button>
        <button class="outline" onclick="editUser('${esc(u.id)}')">✏️ ویرایش</button>
        <button class="danger" onclick="deleteUser('${esc(u.id)}')">🗑️ حذف</button>
      </div>
    </article>`;
  }).join("");
}

function openUser() {
  document.getElementById("user-form").reset();
  document.getElementById("edit-id").value = "";
  document.getElementById("username").disabled = false;
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
  if (!confirm("حذف شود؟")) return;
  await api("/api/users/" + encodeURIComponent(id), { method: "DELETE" });
  loadAll();
}

function openIps() { document.getElementById("ip-dialog").showModal(); renderIps(); }
function renderIps() {
  document.getElementById("ip-list").innerHTML = ipsCache.map(i => `<div class="ip row"><code>${esc(i.ip)}</code><button class="danger" onclick="deleteIp('${i.id}')">حذف</button></div>`).join("");
}
async function saveIp() {
  const ip = document.getElementById("ip-input").value.trim();
  if (!ip) return;
  await api("/api/set-clean-ip", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ip}) });
  document.getElementById("ip-input").value = "";
  loadAll();
}
async function deleteIp(id) {
  await api("/api/delete-ip/" + encodeURIComponent(id), { method: "DELETE" });
  loadAll();
}

loadAll();
