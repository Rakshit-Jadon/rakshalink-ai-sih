/**
 * content.js
 * Runs in every page (document_start). Two jobs:
 *  1. If background flags this page MEDIUM risk, show a dismissible banner.
 *  2. Regardless of navigation-time score, watch the DOM for password/PIN-like
 *     input fields and re-run heuristics + a DOM-content check. If a page
 *     that looks like a bank/UPI login was NOT served from a known-good
 *     domain, intercept focus on that field once and force an explicit
 *     "I trust this site" click before typing is allowed.
 */

(() => {
  const PIN_FIELD_PATTERN = /pin|otp|password|passwd|cvv|mpin|upi/i;
  const UPI_CONTEXT_WORDS = ["upi", "vpa", "pin", "net banking", "netbanking", "debit card", "credit card"];

  let guardedOnce = false;

  function currentResult() {
    return RakshaHeuristics.evaluateUrl(location.href);
  }

  function injectBanner(result) {
    if (document.getElementById("rakshalink-banner")) return;
    const bar = document.createElement("div");
    bar.id = "rakshalink-banner";
    bar.className = "rakshalink-banner";
    bar.innerHTML = `
      <span class="rl-icon">⚠</span>
      <span class="rl-text">This page has some traits seen in phishing sites (risk score ${result.score}/100). Be cautious before entering any bank details.</span>
      <button class="rl-details">Why?</button>
      <button class="rl-dismiss" aria-label="Dismiss">✕</button>
    `;
    document.documentElement.prepend(bar);

    bar.querySelector(".rl-dismiss").addEventListener("click", () => bar.remove());
    bar.querySelector(".rl-details").addEventListener("click", () => {
      alert("RakshaLink flagged this page because:\n\n" + result.reasons.map(r => "• " + r).join("\n"));
    });
  }

  function pageMentionsFinance() {
    const text = document.body ? document.body.innerText.toLowerCase() : "";
    return UPI_CONTEXT_WORDS.some(w => text.includes(w));
  }

  function guardField(field, result) {
    if (guardedOnce) return;
    field.addEventListener("focus", function handler(e) {
      e.target.blur();
      showFieldWarningModal(result, () => {
        field.removeEventListener("focus", handler);
        field.focus();
        guardedOnce = true;
      });
    }, { once: true });
  }

  function showFieldWarningModal(result, onProceed) {
    if (document.getElementById("rakshalink-modal")) return;
    const wrap = document.createElement("div");
    wrap.id = "rakshalink-modal";
    wrap.className = "rakshalink-modal-backdrop";
    wrap.innerHTML = `
      <div class="rl-modal">
        <h2>Hold on — check this site before you type</h2>
        <p>You're about to enter a PIN, password, or OTP on <strong>${location.hostname}</strong>, a site RakshaLink hasn't verified as an official bank/UPI domain.</p>
        <ul>${result.reasons.length ? result.reasons.map(r => `<li>${r}</li>`).join("") : "<li>No official-domain match found for this page.</li>"}</ul>
        <p class="rl-tip">Genuine banks and NPCI/UPI apps never ask you to enter your PIN to "receive" a payment or "reverse" a transaction.</p>
        <div class="rl-actions">
          <button class="rl-cancel">Leave this page</button>
          <button class="rl-proceed">I've verified this site — continue</button>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);
    wrap.querySelector(".rl-cancel").addEventListener("click", () => {
      window.history.back();
      wrap.remove();
    });
    wrap.querySelector(".rl-proceed").addEventListener("click", () => {
      wrap.remove();
      onProceed();
    });
  }

  function scanForSensitiveFields(result) {
    const inputs = document.querySelectorAll("input");
    inputs.forEach(inp => {
      const hay = `${inp.name} ${inp.id} ${inp.placeholder} ${inp.autocomplete}`.toLowerCase();
      const isPasswordType = inp.type === "password";
      const looksLikePin = PIN_FIELD_PATTERN.test(hay) || (inp.maxLength > 0 && inp.maxLength <= 6 && inp.inputMode === "numeric");
      if (isPasswordType || looksLikePin) {
        guardField(inp, result);
      }
    });
  }

  function init() {
    const result = currentResult();

    if (result.band === "MEDIUM") {
      document.addEventListener("DOMContentLoaded", () => injectBanner(result));
    }

    // Only bother scanning the DOM for sensitive fields if either the URL
    // heuristics raised some concern, OR the page content itself talks about
    // UPI/banking (covers the case where the URL alone scored LOW but the
    // page is a freshly-registered clone with a clean-looking domain).
    const shouldScan = () => result.band !== "LOW" || pageMentionsFinance();

    const observer = new MutationObserver(() => {
      if (shouldScan()) scanForSensitiveFields(result);
    });

    document.addEventListener("DOMContentLoaded", () => {
      if (shouldScan()) scanForSensitiveFields(result);
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  init();
})();
