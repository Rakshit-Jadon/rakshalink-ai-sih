(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  document.getElementById("hostname").textContent = tab.url || "";

  let result = await chrome.runtime.sendMessage({ type: "GET_TAB_RISK", tabId: tab.id });
  if (!result && tab.url) {
    result = await chrome.runtime.sendMessage({ type: "EVALUATE_URL", url: tab.url });
  }
  if (!result) return;

  const card = document.getElementById("statusCard");
  const scoreEl = document.getElementById("scoreText");
  const bandEl = document.getElementById("bandText");
  const list = document.getElementById("reasonsList");

  card.classList.remove("status-low", "status-medium", "status-high");
  const bandClass = { LOW: "status-low", MEDIUM: "status-medium", HIGH: "status-high" }[result.band] || "status-low";
  card.classList.add(bandClass);

  scoreEl.textContent = result.score;
  const labels = {
    LOW: "No phishing signals detected on this page.",
    MEDIUM: "Some caution advised — a few risk signals found.",
    HIGH: "High risk — this looked like a spoofed bank/UPI page."
  };
  bandEl.textContent = labels[result.band] || "";

  list.innerHTML = "";
  if (!result.reasons || result.reasons.length === 0) {
    list.innerHTML = '<li class="empty">No concerns on this page.</li>';
  } else {
    result.reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });
  }
})();
