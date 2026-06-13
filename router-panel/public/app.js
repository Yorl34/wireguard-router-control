let state = null;
let selectedId = null;
let selectedClientId = null;

const THEME_KEY = "wr-control-theme";

const $ = (id) => document.getElementById(id);
const fields = ["name", "site", "wgIp", "lanIp", "lanCidr", "model", "notes"];
const checkboxFields = ["allowLan"];
const clientFields = {
  name: "clientName",
  deviceType: "clientType",
  wgIp: "clientWgIp",
  notes: "clientNotes",
};
const clientCheckboxFields = ["clientAllowLan"];

function getTheme() {
  return localStorage.getItem(THEME_KEY) || "light";
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem(THEME_KEY, theme);
  const button = $("themeToggle");
  if (button) {
    const next = theme === "dark" ? "light" : "dark";
    button.setAttribute("aria-label", theme === "dark" ? "Включить светлую тему" : "Включить тёмную тему");
    button.title = theme === "dark" ? "Включить светлую тему" : "Включить тёмную тему";
    button.dataset.nextTheme = next;
  }
}

function toggleTheme() {
  setTheme(getTheme() === "dark" ? "light" : "dark");
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(await res.text());
  const type = res.headers.get("content-type") || "";
  return type.includes("application/json") ? res.json() : res.text();
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[ch]));
}

function routerCardHtml(router) {
  return `
    <span class="router-status-dot ${esc(router.runtimeStatus || "expected")}"></span>
    <span class="router-item-main">
      <strong>${esc(router.name)}</strong>
      <span>${esc(router.wgIp)} · ${esc(router.site || router.lanIp)}</span>
      <small>${esc(router.runtimeText || "Ожидается")} · ${esc(router.lastHandshakeText || "ещё не подключался")}</small>
    </span>`;
}

function renderList() {
  const filter = $("filter").value.trim().toLowerCase();
  const list = $("routerList");
  list.innerHTML = "";
  state.routers
    .filter((router) => {
      const hay = `${router.name} ${router.site} ${router.wgIp} ${router.lanIp}`.toLowerCase();
      return hay.includes(filter);
    })
    .forEach((router) => {
      const btn = document.createElement("button");
      btn.dataset.routerId = router.id;
      btn.className = `router-item ${router.id === selectedId ? "active" : ""}`;
      btn.innerHTML = routerCardHtml(router);
      btn.onclick = () => selectRouter(router.id);
      list.appendChild(btn);
    });
}

function updateRouterCard(router) {
  const btn = document.querySelector(`.router-item[data-router-id="${router.id}"]`);
  if (!btn) return;
  btn.className = `router-item ${router.id === selectedId ? "active" : ""}`;
  btn.innerHTML = routerCardHtml(router);
}

function populateSelectedRouterView(router) {
  if (!router) return;
  fields.forEach((field) => ($(field).value = router[field] || ""));
  checkboxFields.forEach((field) => ($(field).checked = router[field] !== false));
  updateSelectedRouterStatus(router);
}

function updateSelectedRouterStatus(router) {
  if (!router) return;
  $("editorTitle").innerHTML = `<span class="router-status-dot ${esc(router.runtimeStatus || "expected")}"></span>${esc(router.name)}`;
  $("editorSubtitle").textContent = `${router.runtimeText || "Ожидается"} · ${router.lastHandshakeText || "ещё не подключался"} · ${router.wgIp} · LAN ${router.lanIp}${router.allowLan !== false ? ` · маршрут ${router.lanCidr || ""}` : ""}`;
}

function selectedRouter() {
  return state.routers.find((router) => router.id === selectedId);
}

function collectLanRoutes() {
  const seen = new Set();
  const routes = [];
  (state.routers || []).forEach((router) => {
    if (router.allowLan === false) return;
    const route = String(router.lanCidr || "").trim();
    if (!route || seen.has(route)) return;
    seen.add(route);
    routes.push(route);
  });
  return routes;
}

function clientTypeLabel(type) {
  return {
    phone: "Телефон",
    laptop: "Ноутбук",
    pc: "ПК",
    tablet: "Планшет",
    other: "Другое",
  }[type] || "Устройство";
}

function clientCardHtml(client) {
  return `
    <span class="router-status-dot ${esc(client.runtimeStatus || "expected")}"></span>
    <span class="router-item-main">
      <strong>${esc(client.name)}</strong>
      <span>${esc(client.wgIp)} · ${esc(clientTypeLabel(client.deviceType))}</span>
      <small>${esc(client.runtimeText || "Ожидается")} · ${esc(client.lastHandshakeText || "ещё не подключался")}</small>
    </span>`;
}

function renderClients() {
  const filter = $("clientFilter").value.trim().toLowerCase();
  const list = $("clientList");
  list.innerHTML = "";
  (state.clients || [])
    .filter((client) => {
      const hay = `${client.name} ${client.deviceType} ${client.wgIp} ${client.notes}`.toLowerCase();
      return hay.includes(filter);
    })
    .forEach((client) => {
      const btn = document.createElement("button");
      btn.dataset.clientId = client.id;
      btn.className = `router-item ${client.id === selectedClientId ? "active" : ""}`;
      btn.innerHTML = clientCardHtml(client);
      btn.onclick = () => selectClient(client.id);
      list.appendChild(btn);
    });
}

function updateClientCard(client) {
  const btn = document.querySelector(`.router-item[data-client-id="${client.id}"]`);
  if (!btn) return;
  btn.className = `router-item ${client.id === selectedClientId ? "active" : ""}`;
  btn.innerHTML = clientCardHtml(client);
}

function selectedClient() {
  return (state.clients || []).find((client) => client.id === selectedClientId);
}

function selectRouter(id) {
  selectedId = id;
  const router = selectedRouter();
  $("empty").classList.toggle("hidden", Boolean(router));
  $("editor").classList.toggle("hidden", !router);
  renderList();
  if (!router) return;
  populateSelectedRouterView(router);
  renderOutputs(router);
}

function accessClientConfig(client) {
  const s = state.settings;
  const allowedIps = [s.wgCidr || "10.66.66.0/24"];
  if (client.allowLan !== false) {
    collectLanRoutes().forEach((route) => {
      if (route && !allowedIps.includes(route)) allowedIps.push(route);
    });
  }
  return `[Interface]
PrivateKey = ${client.privateKey || ""}
Address = ${client.wgIp}/32
DNS = ${s.dns || "1.1.1.1"}

[Peer]
PublicKey = ${s.serverPublicKey}
PresharedKey = ${client.presharedKey || ""}
Endpoint = ${s.serverEndpoint}:${s.serverPort}
AllowedIPs = ${allowedIps.join(", ")}
PersistentKeepalive = 25
`;
}

function selectClient(id) {
  selectedClientId = id;
  const client = selectedClient();
  $("clientEmpty").classList.toggle("hidden", Boolean(client));
  $("clientEditor").classList.toggle("hidden", !client);
  renderClients();
  if (!client) return;
  Object.entries(clientFields).forEach(([key, elementId]) => ($(elementId).value = client[key] || ""));
  clientCheckboxFields.forEach((id) => ($(id).checked = client.allowLan !== false));
  renderClientOutputs(client);
}

function updateSelectedClientStatus(client) {
  if (!client) return;
  $("clientTitle").innerHTML = `<span class="router-status-dot ${esc(client.runtimeStatus || "expected")}"></span>${esc(client.name)}`;
  const routes = client.allowLan !== false ? collectLanRoutes() : [];
  $("clientSubtitle").textContent = `${client.runtimeText || "Ожидается"} · ${client.lastHandshakeText || "ещё не подключался"} · ${client.wgIp} · ${clientTypeLabel(client.deviceType)}${routes.length ? ` · LAN ${routes.join(", ")}` : ""}`;
}

function renderClientOutputs(client) {
  const config = accessClientConfig(client);
  $("clientConfig").value = config;
  $("clientQr").src = `/api/qr?text=${encodeURIComponent(config)}`;
  $("clientKeys").value = `PublicKey = ${client.publicKey || ""}
PrivateKey = ${client.privateKey || ""}
PresharedKey = ${client.presharedKey || ""}`;
  updateSelectedClientStatus(client);
  setClientStatus("");
}

function setClientStatus(text, type = "") {
  const el = $("clientStatus");
  el.textContent = text;
  el.className = `status-line ${type}`.trim();
}

function openwrtScript(router) {
  const s = state.settings;
  const lanEnabled = router.allowLan !== false;
  const lanForward = lanEnabled
    ? `

# 6. Allow traffic from WireGuard to the LAN zone.
uci -q delete firewall.wg_lan
uci set firewall.wg_lan='forwarding'
uci set firewall.wg_lan.src='wg'
uci set firewall.wg_lan.dest='lan'
`
    : "";
  return `# ${router.name} -> ${s.serverName}
# Paste into OpenWrt SSH as root.

# 1. Update package lists and install WireGuard support.
opkg update
opkg install kmod-wireguard wireguard-tools luci-proto-wireguard

# 2. Remove old wg0 and firewall entries if they exist.
uci -q delete network.wg0
uci -q delete network.wg0_peer
uci -q delete firewall.wg
uci -q delete firewall.wg_lan

# 3. Create the wg0 interface on the router.
uci set network.wg0='interface'
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${router.privateKey || ""}'
uci add_list network.wg0.addresses='${router.wgIp}/32'

# 4. Add the VPS as the WireGuard peer.
uci set network.wg0_peer='wireguard_wg0'
uci set network.wg0_peer.description='${s.serverName}'
uci set network.wg0_peer.public_key='${s.serverPublicKey}'
uci set network.wg0_peer.preshared_key='${router.presharedKey || ""}'
uci set network.wg0_peer.endpoint_host='${s.serverEndpoint}'
uci set network.wg0_peer.endpoint_port='${s.serverPort}'
uci set network.wg0_peer.route_allowed_ips='1'
uci add_list network.wg0_peer.allowed_ips='${s.wgCidr}'
uci set network.wg0_peer.persistent_keepalive='25'

# 5. Allow traffic through the WireGuard zone.
uci set firewall.wg='zone'
uci set firewall.wg.name='wg'
uci set firewall.wg.input='ACCEPT'
uci set firewall.wg.output='ACCEPT'
uci set firewall.wg.forward='REJECT'
uci add_list firewall.wg.network='wg0'
${lanForward}

# 7. Save config files and reboot the router.
uci commit network
uci commit firewall
sync
reboot
`;
}

function peerBlock(router) {
  const allowedIps = [`${router.wgIp}/32`];
  if (router.allowLan !== false && router.lanCidr) {
    allowedIps.push(router.lanCidr);
  }
  return `[Peer]
# ${router.name} | ${router.site || ""} | LAN ${router.lanIp || ""}
PublicKey = ${router.publicKey || ""}
PresharedKey = ${router.presharedKey || ""}
AllowedIPs = ${allowedIps.join(", ")}
`;
}

function renderOutputs(router) {
  $("openwrtOutput").value = openwrtScript(router);
  $("peerOutput").value = peerBlock(router);
  $("keysOutput").value = `PublicKey = ${router.publicKey || ""}
PrivateKey = ${router.privateKey || "(не сохранён для уже установленного роутера)"}
PresharedKey = ${router.presharedKey || ""}`;
  updateSelectedRouterStatus(router);
  setApplyStatus("");
}

function setApplyStatus(text, type = "") {
  const el = $("applyStatus");
  el.textContent = text;
  el.className = `status-line ${type}`.trim();
}

async function load() {
  state = await api("/api/state");
  $("serverEndpoint").value = state.settings.serverEndpoint;
  $("serverPort").value = state.settings.serverPort;
  $("wgCidr").value = state.settings.wgCidr;
  $("serverPublicKey").value = state.settings.serverPublicKey;
  selectedId = state.routers[0]?.id || null;
  selectedClientId = state.clients?.[0]?.id || null;
  renderList();
  selectRouter(selectedId);
  renderClients();
  selectClient(selectedClientId);
}

async function refreshStatus() {
  if (!state) return;
  const previous = selectedId;
  state = await api("/api/state");
  selectedId = previous && state.routers.some((router) => router.id === previous)
    ? previous
    : state.routers[0]?.id || null;
  state.routers.forEach(updateRouterCard);
  const router = selectedRouter();
  $("empty").classList.toggle("hidden", Boolean(router));
  $("editor").classList.toggle("hidden", !router);
  if (router) updateSelectedRouterStatus(router);
  selectedClientId = selectedClientId && (state.clients || []).some((client) => client.id === selectedClientId)
    ? selectedClientId
    : state.clients?.[0]?.id || null;
  (state.clients || []).forEach(updateClientCard);
  const client = selectedClient();
  $("clientEmpty").classList.toggle("hidden", Boolean(client));
  $("clientEditor").classList.toggle("hidden", !client);
  if (client) {
    updateSelectedClientStatus(client);
    const selected = document.querySelector(`.router-item[data-client-id="${client.id}"]`);
    if (selected) selected.classList.add("active");
  }
}

async function saveSettings() {
  state.settings = await api("/api/settings", {
    method: "POST",
    body: JSON.stringify({
      serverEndpoint: $("serverEndpoint").value.trim(),
      serverPort: Number($("serverPort").value),
      wgCidr: $("wgCidr").value.trim(),
      serverPublicKey: $("serverPublicKey").value.trim(),
    }),
  });
  const router = selectedRouter();
  if (router) renderOutputs(router);
}

async function addRouter() {
  await saveSettings();
  const router = await api("/api/routers", {
    method: "POST",
    body: JSON.stringify({ name: "Новый роутер", allowLan: true }),
  });
  state.routers.push(router);
  selectRouter(router.id);
  const client = selectedClient();
  if (client) renderClientOutputs(client);
}

async function addClient() {
  await saveSettings();
  const client = await api("/api/clients", {
    method: "POST",
    body: JSON.stringify({ name: "Новое устройство", deviceType: "phone", allowLan: true }),
  });
  state.clients = state.clients || [];
  state.clients.push(client);
  selectClient(client.id);
}

async function saveRouter() {
  const payload = {};
  fields.forEach((field) => (payload[field] = $(field).value.trim()));
  checkboxFields.forEach((field) => (payload[field] = $(field).checked));
  const router = await api(`/api/routers/${selectedId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  const index = state.routers.findIndex((item) => item.id === selectedId);
  state.routers[index] = router;
  updateRouterCard(router);
  populateSelectedRouterView(router);
  renderOutputs(router);
  const client = selectedClient();
  if (client) renderClientOutputs(client);
}

async function applyVps() {
  if (!selectedId) return;
  await saveRouter();
  setApplyStatus("Применяю peer на VPS...");
  try {
    const result = await api(`/api/routers/${selectedId}/apply-vps`, { method: "POST" });
    const text = result.removed
      ? "Peer обновлен на VPS, WireGuard перезапущен."
      : "Peer добавлен на VPS, WireGuard перезапущен.";
    setApplyStatus(text, "ok");
  } catch (err) {
    setApplyStatus(`Ошибка применения на VPS: ${err.message}`, "error");
  }
}

async function saveClient() {
  if (!selectedClientId) return;
  const payload = {};
  Object.entries(clientFields).forEach(([key, elementId]) => (payload[key] = $(elementId).value.trim()));
  clientCheckboxFields.forEach((id) => (payload.allowLan = $(id).checked));
  const client = await api(`/api/clients/${selectedClientId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  const index = state.clients.findIndex((item) => item.id === selectedClientId);
  state.clients[index] = client;
  updateClientCard(client);
  renderClientOutputs(client);
}

async function applyClientVps() {
  if (!selectedClientId) return;
  await saveClient();
  setClientStatus("Применяю устройство на VPS...");
  try {
    const result = await api(`/api/clients/${selectedClientId}/apply-vps`, { method: "POST" });
    const text = result.removed
      ? "Устройство обновлено на VPS, WireGuard перезапущен."
      : "Устройство добавлено на VPS, WireGuard перезапущен.";
    setClientStatus(text, "ok");
  } catch (err) {
    setClientStatus(`Ошибка применения на VPS: ${err.message}`, "error");
  }
}

async function deleteClient() {
  if (!selectedClientId || !confirm("Удалить устройство из базы?")) return;
  await api(`/api/clients/${selectedClientId}`, { method: "DELETE" });
  state.clients = state.clients.filter((client) => client.id !== selectedClientId);
  selectedClientId = state.clients[0]?.id || null;
  renderClients();
  selectClient(selectedClientId);
}

async function deleteRouter() {
  if (!selectedId || !confirm("Удалить роутер из базы?")) return;
  await api(`/api/routers/${selectedId}`, { method: "DELETE" });
  state.routers = state.routers.filter((router) => router.id !== selectedId);
  selectedId = state.routers[0]?.id || null;
  renderList();
  selectRouter(selectedId);
  const client = selectedClient();
  if (client) renderClientOutputs(client);
}

async function copyText(id) {
  await navigator.clipboard.writeText($(id).value);
}

async function exportPeers() {
  const text = state.routers.map(peerBlock).join("\n");
  $("allPeers").value = text;
  $("peerDialog").showModal();
  await navigator.clipboard.writeText(text);
}

["serverEndpoint", "serverPort", "wgCidr", "serverPublicKey"].forEach((id) => {
  $(id).addEventListener("change", saveSettings);
});

$("filter").addEventListener("input", renderList);
$("clientFilter").addEventListener("input", renderClients);
$("addRouter").onclick = addRouter;
$("addClient").onclick = addClient;
$("saveRouter").onclick = saveRouter;
$("applyVps").onclick = applyVps;
$("deleteRouter").onclick = deleteRouter;
$("saveClient").onclick = saveClient;
$("applyClientVps").onclick = applyClientVps;
$("deleteClient").onclick = deleteClient;
$("copyOpenwrt").onclick = () => copyText("openwrtOutput");
$("copyPeer").onclick = () => copyText("peerOutput");
$("copyClientConfig").onclick = () => copyText("clientConfig");
$("copyClientQrLink").onclick = async () => navigator.clipboard.writeText($("clientQr").src);
$("exportPeers").onclick = exportPeers;
$("themeToggle").onclick = toggleTheme;

setTheme(getTheme());
load().catch((err) => alert(err.message));
setInterval(() => refreshStatus().catch(() => {}), 30000);
