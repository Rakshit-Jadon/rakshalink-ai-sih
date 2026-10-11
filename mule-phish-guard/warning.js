const params = new URLSearchParams(location.search);
const target = params.get("target") || "";
const score = params.get("score") || "?";
let reasons = [];
try { reasons = JSON.parse(params.get("reasons") || "[]"); } catch (e) {}

document.getElementById("score").textContent = score;
document.getElementById("target").textContent = target;

const list = document.getElementById("reasons");
reasons.forEach(r => {
  const li = document.createElement("li");
  li.textContent = r;
  list.appendChild(li);
});
if (reasons.length === 0) {
  const li = document.createElement("li");
  li.textContent = "Multiple heuristic signals combined pushed this over the block threshold.";
  list.appendChild(li);
}

document.getElementById("goBack").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.href = "https://www.google.com/search?q=is+this+site+safe";
});

document.getElementById("proceed").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "PROCEED_ANYWAY", target });
});
