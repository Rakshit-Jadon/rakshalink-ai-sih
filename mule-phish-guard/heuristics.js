/**
 * heuristics.js
 * ---------------------------------------------------------------------------
 * Pure, dependency-free scoring engine for detecting spoofed bank / UPI
 * domains and credential-phishing pages. Runs entirely on-device — no
 * network calls, no data leaves the browser. Shared between background.js
 * (pre-navigation checks) and content.js (in-page DOM checks).
 *
 * Score bands:
 *   0 - 24   -> LOW      (no action)
 *   25 - 54  -> MEDIUM   (non-blocking in-page banner)
 *   55 - 100 -> HIGH     (full-page interstitial warning)
 * ---------------------------------------------------------------------------
 */

const RakshaHeuristics = (() => {

  // A small seed list of high-value brand domains commonly impersonated in
  // Indian UPI/bank phishing (SMS "your account will be blocked" / fake
  // cashback / KYC-update lures). In production this list is fetched from a
  // signed remote config and cached, so it can grow without an extension
  // update.
  const PROTECTED_BRANDS = {
    "sbi":        ["onlinesbi.sbi", "sbi.co.in", "sbiyono.sbi"],
    "hdfcbank":   ["hdfcbank.com", "netbanking.hdfcbank.com"],
    "icicibank":  ["icicibank.com"],
    "axisbank":   ["axisbank.com"],
    "kotak":      ["kotak.com"],
    "pnb":        ["pnbindia.in", "netpnb.com"],
    "paytm":      ["paytm.com", "paytmbank.com"],
    "phonepe":    ["phonepe.com"],
    "googlepay":  ["pay.google.com"],
    "bhim":       ["npci.org.in", "bhimupi.org.in"],
    "npci":       ["npci.org.in"],
    "amazonpay":  ["amazon.in", "amazonpay.in"]
  };

  const SUSPICIOUS_TLDS = new Set([
    "tk","ml","ga","cf","gq","xyz","top","click","link","work","support",
    "info","loan","win","bid","gdn","country","kim"
  ]);

  const URGENCY_KEYWORDS = [
    "verify","kyc","update","block","suspend","expire","reactivate",
    "cashback","reward","refund","win","lottery","limited","urgent",
    "otp","pin","secure","confirm","penalty","fine","kyc-update"
  ];

  const URL_SHORTENERS = new Set([
    "bit.ly","tinyurl.com","cutt.ly","rebrand.ly","is.gd","t.co","shorturl.at",
    "rb.gy","tiny.cc","bitly.com","short.io"
  ]);

  // --- string distance -------------------------------------------------

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[m][n];
  }

  // Second-level labels that don't carry brand meaning on their own, so the
  // "registrable" domain for e.g. "sbi.co.in" should keep 3 labels, not 2.
  const COMPOUND_SECOND_LEVEL = new Set([
    "co","com","net","org","gov","edu","ac","res","gen","mil","nic"
  ]);

  function registrableDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    const secondToLast = parts[parts.length - 2];
    if (COMPOUND_SECOND_LEVEL.has(secondToLast) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  // --- individual checks -------------------------------------------------

  function checkPunycode(hostname, rawUrl = "") {
    if (hostname.includes("xn--") || rawUrl.toLowerCase().includes("xn--") || /[^\x00-\x7F]/.test(hostname)) {
      return { points: 30, reason: "Domain uses Punycode or non-ASCII lookalike characters (possible homograph attack)" };
    }
    return null;
  }

  function checkIpHost(hostname) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4.test(hostname)) {
      return { points: 35, reason: "Site is addressed by raw IP instead of a domain name" };
    }
    return null;
  }

  function checkProtocol(protocol) {
    if (protocol !== "https:") {
      return { points: 20, reason: "Connection is not encrypted (no HTTPS)" };
    }
    return null;
  }

  function checkSubdomainDepth(hostname) {
    const depth = hostname.split(".").length;
    if (depth >= 5) {
      return { points: 15, reason: `Unusually deep subdomain chain (${depth} labels)` };
    }
    return null;
  }

  function checkAtSymbol(href) {
    // '@' is normal syntax in upi:// deep links (VPA = user@bank) and mailto:.
    if (href.startsWith("upi:") || href.startsWith("mailto:")) return null;
    if (href.includes("@")) {
      return { points: 25, reason: "URL contains '@', a classic redirect-masking trick" };
    }
    return null;
  }

  function checkShortener(hostname) {
    if (URL_SHORTENERS.has(hostname)) {
      return { points: 15, reason: "URL shortener detected — real destination is hidden" };
    }
    return null;
  }

  function checkSuspiciousTld(hostname) {
    const tld = hostname.split(".").pop();
    if (SUSPICIOUS_TLDS.has(tld)) {
      return { points: 10, reason: `Domain uses a TLD frequently abused in phishing (.${tld})` };
    }
    return null;
  }

  function checkUrgencyKeywords(fullUrl) {
    const lower = fullUrl.toLowerCase();
    const hits = URGENCY_KEYWORDS.filter(k => lower.includes(k));
    if (hits.length >= 2) {
      return { points: 15, reason: `Multiple urgency/lure keywords in URL (${hits.slice(0, 3).join(", ")})` };
    }
    return null;
  }

  // Brand impersonation: does the hostname closely resemble a protected
  // brand's real domain while NOT being one of that brand's real domains?
  function checkBrandImpersonation(hostname) {
    const reg = registrableDomain(hostname);
    for (const [brand, realDomains] of Object.entries(PROTECTED_BRANDS)) {
      if (realDomains.includes(reg)) return null; // it IS the real domain
      // Direct brand keyword stuffed into an unrelated domain, e.g.
      // "hdfcbank-kyc-update.xyz" or "sbi-verify.tk"
      if (reg.includes(brand) && !realDomains.includes(reg)) {
        return {
          points: 40,
          reason: `Domain contains brand name "${brand}" but is not an official ${brand} domain`
        };
      }
      // Lookalike via edit distance against each real domain's label
      for (const real of realDomains) {
        const realLabel = real.split(".")[0];
        const hostLabel = reg.split(".")[0];
        const dist = levenshtein(hostLabel, realLabel);
        const closeEnough = (hostLabel.length >= 4 && dist > 0 && dist <= 2) ||
                             (hostLabel.length === 3 && dist === 1);
        if (closeEnough) {
          return {
            points: 45,
            reason: `Domain "${reg}" is a near-identical lookalike of "${real}" (edit distance ${dist})`
          };
        }
      }
    }
    return null;
  }

  function checkMixedScript(hostname) {
    // crude homograph check: latin mixed with cyrillic/greek lookalikes
    const hasLatin = /[a-z]/i.test(hostname);
    const hasCyrillic = /[\u0400-\u04FF]/.test(hostname);
    const hasGreek = /[\u0370-\u03FF]/.test(hostname);
    if (hasLatin && (hasCyrillic || hasGreek)) {
      return { points: 40, reason: "Domain mixes Latin characters with Cyrillic/Greek lookalikes" };
    }
    return null;
  }

  function checkUpiDeepLink(href) {
    if (href.startsWith("upi://") || href.startsWith("upi:pay")) {
      // Real UPI collect/pay links have pa (payee address), pn (payee name).
      // Flag if payee address looks auto-generated / random.
      const match = href.match(/pa=([^&]+)/i);
      if (match) {
        const vpa = decodeURIComponent(match[1]);
        const localPart = vpa.split("@")[0] || "";
        const randomish = /\d{6,}/.test(localPart) || localPart.length > 20;
        if (randomish) {
          return { points: 30, reason: `UPI payee address "${vpa}" looks auto-generated, not a merchant handle` };
        }
      }
    }
    return null;
  }

  /**
   * Evaluate a URL and return a structured risk result.
   * @param {string} rawUrl
   * @returns {{score:number, band:"LOW"|"MEDIUM"|"HIGH", reasons:string[], hostname:string}}
   */
  function evaluateUrl(rawUrl) {
    if (typeof rawUrl !== "string") {
      return { score: 0, band: "LOW", reasons: [], hostname: "" };
    }

    let url;
    const normalized = rawUrl.trim();
    const candidate = /^(https?:)?\/\//i.test(normalized)
      ? normalized
      : `http://${normalized}`;

    try {
      url = new URL(candidate);
    } catch (e) {
      return { score: 0, band: "LOW", reasons: [], hostname: "" };
    }

    const hostname = url.hostname.toLowerCase();
    const checks = [
      checkPunycode(hostname, rawUrl),
      checkIpHost(hostname),
      checkProtocol(url.protocol),
      checkSubdomainDepth(hostname),
      checkAtSymbol(rawUrl),
      checkShortener(hostname),
      checkSuspiciousTld(hostname),
      checkUrgencyKeywords(rawUrl),
      checkBrandImpersonation(hostname),
      checkMixedScript(hostname),
      checkUpiDeepLink(rawUrl)
    ].filter(Boolean);

    const score = Math.min(100, checks.reduce((s, c) => s + c.points, 0));
    const reasons = checks.map(c => c.reason);

    let band = "LOW";
    if (score >= 55) band = "HIGH";
    else if (score >= 25) band = "MEDIUM";

    return { score, band, reasons, hostname };
  }

  return { evaluateUrl, levenshtein, registrableDomain, PROTECTED_BRANDS };
})();

// Support both service-worker (importScripts) and content-script contexts.
if (typeof module !== "undefined") {
  module.exports = RakshaHeuristics;
}
