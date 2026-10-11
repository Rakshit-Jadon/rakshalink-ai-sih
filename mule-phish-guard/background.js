/**
 * background.js — MV3 service worker
 * Evaluates every top-level navigation BEFORE the page finishes loading.
 * MEDIUM/HIGH risk -> redirect to a blocking interstitial (like Safe Browsing).
 * LOW risk -> badge green, no interruption.
 * Scan counts and recent threats are saved in chrome.storage.local.
 */

importScripts("heuristics.js");

const overrides = new Set();
const BLOCKED_BANDS = new Set(["MEDIUM", "HIGH"]);

function badgeFor(band) {
  const map = { LOW: ["OK", "#1B7A4A"], MEDIUM: ["!", "#C98900"], HIGH: ["!!", "#C62828"] };
  return map[band] || ["", "#999999"];
}

async function rememberScan(url, result, blocked) {
  const data = await chrome.storage.local.get(["pagesChecked", "threatsBlocked", "recentScans"]);
  const recent = Array.isArray(data.recentScans) ? data.recentScans : [];
  recent.unshift({
    url,
    hostname: result.hostname,
    score: result.score,
    band: result.band,
    reasons: result.reasons,
    blocked: !!blocked,
    ts: Date.now()
  });
  await chrome.storage.local.set({
    pagesChecked: (data.pagesChecked || 0) + 1,
    threatsBlocked: (data.threatsBlocked || 0) + (blocked ? 1 : 0),
    recentScans: recent.slice(0, 40)
  });
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { url, tabId } = details;
  if (!url.startsWith("http")) return;

  const result = RakshaHeuristics.evaluateUrl(url);
  const [text, color] = badgeFor(result.band);
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });

  await chrome.storage.session.set({
    [`risk_${tabId}`]: { url, ...result, ts: Date.now() }
  });

  const overrideKey = `${tabId}:${url}`;
  const blocked = BLOCKED_BANDS.has(result.band) && !overrides.has(overrideKey);
  await rememberScan(url, result, blocked);

  if (blocked) {
    const warnUrl = chrome.runtime.getURL("warning.html") +
      `?target=${encodeURIComponent(url)}` +
      `&score=${result.score}` +
      `&reasons=${encodeURIComponent(JSON.stringify(result.reasons))}`;
    chrome.tabs.update(tabId, { url: warnUrl });
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "PROCEED_ANYWAY") {
    overrides.add(`${sender.tab.id}:${msg.target}`);
    chrome.tabs.update(sender.tab.id, { url: msg.target });
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === "GET_TAB_RISK") {
    chrome.storage.session.get([`risk_${msg.tabId}`]).then(data => {
      sendResponse(data[`risk_${msg.tabId}`] || null);
    });
    return true;
  }
  if (msg.type === "EVALUATE_URL") {
    sendResponse(RakshaHeuristics.evaluateUrl(msg.url));
    return true;
  }
  if (msg.type === "GET_STATS") {
    chrome.storage.local.get(["pagesChecked", "threatsBlocked", "recentScans"]).then(sendResponse);
    return true;
  }
});
