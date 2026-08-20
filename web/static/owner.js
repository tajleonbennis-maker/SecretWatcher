const $ = id => document.getElementById(id);
const number = value => new Intl.NumberFormat("zh-CN").format(value || 0);
let token = sessionStorage.getItem("secretwatcher-admin-token") || "";

function escapeHtml(value) {
  const span = document.createElement("span"); span.textContent = value ?? ""; return span.innerHTML;
}

async function refresh() {
  const response = await fetch("/api/admin/scan/progress", {headers:{Authorization:`Bearer ${token}`}});
  if (!response.ok) throw new Error(`鉴权失败：${response.status}`);
  const data = await response.json();
  const total = data.total_assets || 0, done = data.completed_assets || 0;
  $("completed").textContent = `${number(done)} / ${number(total)}`;
  $("successful").textContent = number(data.successful_assets);
  $("files").textContent = number(data.files_scanned);
  $("findings").textContent = number(data.findings);
  $("progressBar").style.width = `${total ? Math.min(100, done / total * 100) : 0}%`;
  $("status").textContent = `批次状态：${data.status} · 失败 ${number(data.failed_assets)} · 已分析 ${number(data.bytes_scanned)} 字节 · 更新时间 ${data.updated_at || "—"}`;
  $("recent").innerHTML = (data.recent_assets || []).map(row => `<tr><td>${escapeHtml(row.asset_name)}</td><td>${escapeHtml(row.product)}</td><td>${escapeHtml(row.status)}</td><td>${number(row.files_scanned)}</td><td>${number(row.bytes_scanned)}</td><td>${number(row.findings)}</td><td>${escapeHtml(row.scanned_at)}</td></tr>`).join("");
}

function render(data) {
  const total = data.total_assets || 0, done = data.completed_assets || 0;
  $("completed").textContent = `${number(done)} / ${number(total)}`;
  $("successful").textContent = number(data.successful_assets);
  $("files").textContent = number(data.files_scanned);
  $("findings").textContent = number(data.findings);
  $("progressBar").style.width = `${total ? Math.min(100, done / total * 100) : 0}%`;
  $("status").textContent = `批次状态：${data.status} · 失败 ${number(data.failed_assets)} · 已分析 ${number(data.bytes_scanned)} 字节 · 更新时间 ${data.updated_at || "—"}`;
  $("recent").innerHTML = (data.recent_assets || []).map(row => `<tr><td>${escapeHtml(row.asset_name)}</td><td>${escapeHtml(row.product)}</td><td>${escapeHtml(row.status)}</td><td>${number(row.files_scanned)}</td><td>${number(row.bytes_scanned)}</td><td>${number(row.findings)}</td><td>${escapeHtml(row.scanned_at)}</td></tr>`).join("");
}

async function streamProgress() {
  const response = await fetch("/api/admin/scan/stream", {headers:{Authorization:`Bearer ${token}`}});
  if (!response.ok || !response.body) throw new Error(`事件流失败：${response.status}`);
  const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = "";
  while (true) {
    const {value, done} = await reader.read(); if (done) break;
    buffer += decoder.decode(value, {stream:true});
    const blocks = buffer.split("\n\n"); buffer = blocks.pop() || "";
    for (const block of blocks) {
      const line = block.split("\n").find(item => item.startsWith("data: "));
      if (line) render(JSON.parse(line.slice(6)).progress);
    }
  }
}

async function connect() {
  token = $("token").value.trim() || token;
  try { const first = await refresh(); sessionStorage.setItem("secretwatcher-admin-token", token); $("login").style.display="none"; $("dashboard").style.display="block"; loadFindings().catch(()=>{}); streamProgress().catch(()=>setInterval(() => refresh().catch(()=>{}), 3000)); }
  catch (error) { $("loginError").textContent = error.message; }
}

function statusLabel(value) {
  return ({ unverified: "待复核", confirmed: "已确认", notified: "已通知", resolved: "已处置" })[value] || value;
}

function findingRow(item) {
  return `<tr>
    <td><b>${escapeHtml(item.provider)}</b></td>
    <td>${escapeHtml(item.product)}<small>${escapeHtml(item.asset)}</small></td>
    <td><code>${escapeHtml(item.models || "未识别模型")}</code></td>
    <td><code>${escapeHtml(item.key_hint)}</code></td>
    <td>${Number(item.confidence || 0).toFixed(2)}</td>
    <td>${escapeHtml(statusLabel(item.status))}</td>
    <td>${escapeHtml(item.last_seen)}</td>
    <td><button class="del" data-id="${Number(item.id)}">删除</button></td>
  </tr>`;
}

async function loadFindings() {
  const response = await fetch("/api/public/findings", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`加载失败：${response.status}`);
  const data = await response.json();
  const list = data.findings || [];
  const body = document.querySelector("#findingsList");
  if (!list.length) { body.innerHTML = `<tr><td colspan="8" class="muted">暂无发现记录</td></tr>`; return; }
  body.innerHTML = list.map(findingRow).join("");
  body.querySelectorAll("button.del").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm(`确认删除发现记录 #${btn.dataset.id}？`)) return;
      const resp = await fetch(`/api/admin/findings/${btn.dataset.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (resp.ok) { loadFindings().catch(()=>{}); } else { alert(`删除失败：${resp.status}`); }
    });
  });
}

$("connect").addEventListener("click", connect);
if (token) connect();
