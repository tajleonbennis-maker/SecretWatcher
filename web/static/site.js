const number = value => new Intl.NumberFormat("zh-CN").format(value || 0);

async function loadPublicData() {
  try {
    const [statsResponse, coverageResponse, findingsResponse] = await Promise.all([
      fetch("/api/public/stats", { headers: { Accept: "application/json" } }),
      fetch("/api/public/coverage", { headers: { Accept: "application/json" } }),
      fetch("/api/public/findings", { headers: { Accept: "application/json" } }),
    ]);
    if (!statsResponse.ok || !coverageResponse.ok || !findingsResponse.ok) throw new Error("public api unavailable");
    const stats = await statsResponse.json();
    const coverage = await coverageResponse.json();
    const findings = await findingsResponse.json();
    document.querySelector("#assetsStat").textContent = number(stats.assets_observed);
    document.querySelector("#detectionsStat").textContent = number(stats.detections);
    document.querySelector("#productsStat").textContent = number(stats.products);
    document.querySelector("#coverageCount").textContent = number(coverage.count);
    document.querySelector("#productGrid").innerHTML = coverage.products
      .map(product => `<span>${escapeHtml(product)}</span>`).join("") + "<span>更多规则持续加入</span>";
    renderFindings(findings.findings || []);
  } catch (_) {
    document.querySelector("#coverageCount").textContent = "13";
    renderFindings([], "脱敏发现记录暂时无法读取");
  }
}

function renderFindings(findings, emptyMessage = "尚无可公开的脱敏发现记录") {
  const body = document.querySelector("#publicFindings");
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="8" class="findings-empty">${escapeHtml(emptyMessage)}</td></tr>`;
    return;
  }
  body.innerHTML = findings.map(item => `<tr>
    <td><b>${escapeHtml(item.provider)}</b></td>
    <td>${escapeHtml(item.product)}<small>${escapeHtml(item.asset)}</small></td>
    <td><code>${escapeHtml(item.models || "未识别模型")}</code></td>
    <td><code>${escapeHtml(item.key_hint)}</code></td>
    <td><span class="risk risk-${escapeHtml(item.risk_level)}">${escapeHtml(item.risk_level)}</span></td>
    <td>${escapeHtml(formatDate(item.last_seen))}</td>
    <td>${escapeHtml(statusLabel(item.status))}</td>
    <td>${item.evidence ? `<a href="${escapeHtml(item.evidence)}" target="_blank" rel="noreferrer"><img class="evidence-thumb" src="${escapeHtml(item.evidence)}" alt="证据截图" loading="lazy"></a>` : "—"}</td>
  </tr>`).join("");
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

function statusLabel(value) {
  return ({ unverified: "待复核", confirmed: "已确认", notified: "已通知", resolved: "已处置" })[value] || value;
}

function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}

loadPublicData();
