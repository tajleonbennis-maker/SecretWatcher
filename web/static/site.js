const number = value => new Intl.NumberFormat("zh-CN").format(value || 0);

async function loadPublicData() {
  try {
    const [statsResponse, coverageResponse] = await Promise.all([
      fetch("/api/public/stats", { headers: { Accept: "application/json" } }),
      fetch("/api/public/coverage", { headers: { Accept: "application/json" } }),
    ]);
    if (!statsResponse.ok || !coverageResponse.ok) throw new Error("public api unavailable");
    const stats = await statsResponse.json();
    const coverage = await coverageResponse.json();
    document.querySelector("#assetsStat").textContent = number(stats.assets_observed);
    document.querySelector("#detectionsStat").textContent = number(stats.detections);
    document.querySelector("#productsStat").textContent = number(stats.products);
    document.querySelector("#coverageCount").textContent = number(coverage.count);
    document.querySelector("#productGrid").innerHTML = coverage.products
      .map(product => `<span>${escapeHtml(product)}</span>`).join("") + "<span>更多规则持续加入</span>";
  } catch (_) {
    document.querySelector("#coverageCount").textContent = "13";
  }
}

function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}

loadPublicData();

