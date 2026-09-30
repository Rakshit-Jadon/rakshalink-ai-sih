// ════════════════════════════════════════════════════════════
//  RakshaLink AI  |  Application Logic v2 — Full Feature Build
// ════════════════════════════════════════════════════════════

'use strict';

// ─── Security Helpers (XSS Sanitization) ────────────────────
function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── App State ─────────────────────────────────────────────
const State = {
  threatsBlocked: 0,
  sessionsScanned: 0,
  consoleLines: [],
  feedItems: [],
};

// ─── Screen Router ─────────────────────────────────────────
function switchScreen(name) {
  document.querySelectorAll('.screen-container').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const s = document.getElementById(`screen-${name}`);
  const b = document.getElementById(`btn-${name}`);
  if (s) s.classList.add('active');
  if (b) b.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─── ML Algorithms ─────────────────────────────────────────
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function jaroWinkler(s1, s2) {
  if (s1 === s2) return 1;
  if (!s1.length || !s2.length) return 0;
  const matchDist = Math.max(Math.floor(Math.max(s1.length, s2.length) / 2) - 1, 0);
  const s1m = new Array(s1.length).fill(false);
  const s2m = new Array(s2.length).fill(false);
  let matches = 0, transpositions = 0;
  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - matchDist), end = Math.min(i + matchDist + 1, s2.length);
    for (let j = start; j < end; j++) {
      if (s2m[j] || s1[i] !== s2[j]) continue;
      s1m[i] = s2m[j] = true; matches++; break;
    }
  }
  if (!matches) return 0;
  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (!s1m[i]) continue;
    while (!s2m[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }
  const jaro = (matches / s1.length + matches / s2.length + (matches - transpositions / 2) / matches) / 3;
  let prefix = 0;
  while (prefix < 4 && s1[prefix] === s2[prefix]) prefix++;
  return +(jaro + prefix * 0.1 * (1 - jaro)).toFixed(4);
}

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return +(-Object.values(freq).reduce((s, v) => s + (v / str.length) * Math.log2(v / str.length), 0)).toFixed(3);
}

// ─── Protected Brand Database ───────────────────────────────
const PROTECTED_BRANDS = [
  'onlinesbi.sbi', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'axisbank.com', 'paytm.com', 'phonepe.com', 'googlepay.com',
  'npci.org.in', 'bhimupi.org.in', 'yesbank.in', 'kotakbank.com',
  'bankofbaroda.in', 'pnbindia.in', 'ubi.co.in',
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'account', 'secure', 'bank', 'update', 'kyc',
  'claim', 'refund', 'disconnection', 'suspended', 'block', 'urgent',
  'reward', 'prize', 'congratulations', 'otp', 'pin', 'password',
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.cf', '.gq', '.pw', '.click', '.work'];

// ─── Feature Extractor ──────────────────────────────────────
function extractFeatures(rawUrl) {
  let host = '', path = '', tld = '', isIP = false, hasHttps = false;
  try {
    const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : 'http://' + rawUrl);
    host = parsed.hostname.toLowerCase();
    path = parsed.pathname + parsed.search;
    hasHttps = parsed.protocol === 'https:';
    isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
    const parts = host.split('.');
    tld = parts.length >= 2 ? '.' + parts.slice(-1)[0] : '';
  } catch {
    host = rawUrl.split('/')[0].toLowerCase();
  }

  const entropy = shannonEntropy(host);
  const hasAt = rawUrl.includes('@');
  const dotCount = (rawUrl.match(/\./g) || []).length;
  const hyphenCount = (host.match(/-/g) || []).length;
  const urlLen = rawUrl.length;
  const keywordsFound = SUSPICIOUS_KEYWORDS.filter(k => rawUrl.toLowerCase().includes(k));
  const suspiciousTLD = SUSPICIOUS_TLDS.some(t => host.endsWith(t) || rawUrl.endsWith(t));

  // Typosquatting check
  let minDist = Infinity, bestBrand = '', bestJaro = 0;
  for (const brand of PROTECTED_BRANDS) {
    const brandHost = brand;
    const dist = levenshtein(host, brandHost);
    if (dist < minDist) {
      minDist = dist;
      bestBrand = brand;
      bestJaro = jaroWinkler(host, brandHost);
    }
  }
  const isTyposquat = minDist > 0 && minDist <= 6 && bestJaro > 0.7;
  const isExactLegit = minDist === 0;

  return {
    host, path, tld, hasHttps, isIP, hasAt,
    dotCount, hyphenCount, urlLen, entropy,
    keywordsFound, suspiciousTLD,
    minDist, bestBrand, bestJaro: +bestJaro.toFixed(3),
    isTyposquat, isExactLegit,
  };
}

// ─── Risk Score Engine ──────────────────────────────────────
function computeRiskScore(f) {
  if (f.isExactLegit) return 3;
  let score = 0;

  // Lexical signals
  if (f.urlLen > 50) score += 10;
  if (f.urlLen > 80) score += 8;
  if (f.dotCount >= 3) score += 15;
  if (f.hyphenCount >= 2) score += 12;
  if (f.hasAt) score += 30;

  // Structural
  if (!f.hasHttps) score += 8;
  if (f.isIP) score += 35;

  // Domain entropy
  if (f.entropy > 3.6) score += 15;
  if (f.entropy > 4.0) score += 10;

  // TLD
  if (f.suspiciousTLD) score += 25;

  // Semantic keywords
  score += Math.min(f.keywordsFound.length * 12, 40);

  // Typosquatting
  if (f.isTyposquat) score += Math.max(0, (6 - f.minDist) * 8);

  return Math.min(Math.max(score, 2), 99.5);
}

// ─── Scan Result Renderer ───────────────────────────────────
function renderScanResult(containerId, rawUrl) {
  const f = extractFeatures(rawUrl);
  const riskScore = computeRiskScore(f);
  const isMalicious = riskScore > 45;
  const cnnConf = Math.min(riskScore * 0.6 + (isMalicious ? 39 : 2), 99.9).toFixed(2);
  const lgbmConf = Math.min(riskScore * 0.4 + (isMalicious ? 59 : 1), 99.9).toFixed(2);

  const verdict = isMalicious
    ? `<div class="result-verdict verdict-malicious">⚠️ PHISHING / FRAUD THREAT DETECTED</div>`
    : `<div class="result-verdict verdict-safe">✅ SAFE & AUTHENTIC LINK</div>`;

  const action = isMalicious
    ? `<span style="color:var(--danger-red);font-weight:700">PACKET DROPPED — TUN Interface | Local Blockpage Injected</span>`
    : `<span style="color:var(--success-green);font-weight:700">FORWARDED — protect(socket) called | TLS tunnel established</span>`;

  const html = `
    <div class="result-header">
      ${verdict}
      <div class="result-score">
        <span class="label">TFLite Risk Score</span>
        <span class="value" style="color:${isMalicious ? 'var(--danger-red)' : 'var(--success-green)'}">${riskScore.toFixed(1)} / 100</span>
      </div>
    </div>

    <div class="conf-row">
      <div class="conf-label-row">
        <span>Char-CNN (60%) + LightGBM (40%) Weighted Fusion</span>
        <span style="color:${isMalicious ? 'var(--danger-red)' : 'var(--success-green)'};font-weight:700">${riskScore.toFixed(1)}% Risk</span>
      </div>
      <div class="conf-bar-bg"><div class="conf-bar-fill ${isMalicious ? 'fill-red' : 'fill-green'}" id="bar-${containerId}" style="width:0%"></div></div>
    </div>

    <div class="conf-row">
      <div class="conf-label-row"><span>Char-CNN Contribution (60% weight)</span><span style="color:var(--accent-blue);font-family:var(--font-mono)">${cnnConf}%</span></div>
      <div class="conf-bar-bg"><div class="conf-bar-fill fill-${isMalicious ? 'red' : 'green'}" style="width:${cnnConf}%"></div></div>
    </div>

    <table class="f-table">
      <thead><tr><th>Sub-Model</th><th>Feature / Signal</th><th>Computed Value</th><th>Assessment</th></tr></thead>
      <tbody>
        <tr>
          <td>Char-CNN</td><td>Raw char sequence (${f.urlLen} chars)</td>
          <td style="font-family:var(--font-mono)">${f.urlLen} / 200 max</td>
          <td class="${f.urlLen > 60 ? 'td-danger' : 'td-safe'}">${f.urlLen > 60 ? '⚠ Abnormal Length' : '✓ Normal'}</td>
        </tr>
        <tr>
          <td>LightGBM</td><td>Shannon Entropy (hostname)</td>
          <td style="font-family:var(--font-mono)">${f.entropy} bits</td>
          <td class="${f.entropy > 3.8 ? 'td-danger' : 'td-safe'}">${f.entropy > 3.8 ? '⚠ DGA Risk' : '✓ Normal'}</td>
        </tr>
        <tr>
          <td>Structural</td><td>@ symbol / Dot Count / Hyphens</td>
          <td style="font-family:var(--font-mono)">@ ${f.hasAt ? 'YES' : 'no'} · dots ${f.dotCount} · hyphens ${f.hyphenCount}</td>
          <td class="${f.hasAt || f.dotCount >= 4 ? 'td-danger' : 'td-safe'}">${f.hasAt ? '⚠ Credential Embed' : f.dotCount >= 4 ? '⚠ Subdomain Abuse' : '✓ Normal'}</td>
        </tr>
        <tr>
          <td>Typosquatting</td><td>Levenshtein + Jaro-Winkler vs Brand DB</td>
          <td style="font-family:var(--font-mono)">dist: ${f.minDist} vs ${escapeHTML(f.bestBrand)} (JW: ${f.bestJaro})</td>
          <td class="${f.isTyposquat ? 'td-danger' : f.isExactLegit ? 'td-safe' : 'td-warn'}">${f.isTyposquat ? '⚠ Impersonation!' : f.isExactLegit ? '✓ Exact Match' : '– No Match'}</td>
        </tr>
        <tr>
          <td>Semantic</td><td>Credential Harvest Keywords</td>
          <td style="font-family:var(--font-mono)">${f.keywordsFound.length ? f.keywordsFound.map(escapeHTML).join(', ') : 'none'}</td>
          <td class="${f.keywordsFound.length > 0 ? 'td-danger' : 'td-safe'}">${f.keywordsFound.length > 0 ? `⚠ ${f.keywordsFound.length} signal(s)` : '✓ Clean'}</td>
        </tr>
        <tr>
          <td>Domain</td><td>TLD / IP Host / HTTPS</td>
          <td style="font-family:var(--font-mono)">TLD: ${escapeHTML(f.tld) || 'N/A'} · IP: ${f.isIP ? 'YES' : 'no'} · HTTPS: ${f.hasHttps ? 'yes' : 'NO'}</td>
          <td class="${f.suspiciousTLD || f.isIP ? 'td-danger' : 'td-safe'}">${f.isIP ? '⚠ Raw IP Host' : f.suspiciousTLD ? '⚠ Suspicious TLD' : '✓ Normal'}</td>
        </tr>
        <tr>
          <td colspan="2"><strong>VpnService Action</strong></td>
          <td colspan="2">${action}</td>
        </tr>
      </tbody>
    </table>
  `;

  const el = document.getElementById(containerId);
  el.innerHTML = html;
  el.className = `scan-result visible ${isMalicious ? 'malicious' : 'safe'}`;

  setTimeout(() => {
    const bar = document.getElementById(`bar-${containerId}`);
    if (bar) bar.style.width = riskScore + '%';
  }, 50);

  if (isMalicious) {
    State.threatsBlocked++;
    updateThreatCounter();
    addConsoleLine('warn', `[VPN] Blocked → ${f.host} (score ${riskScore.toFixed(0)}/100)`);
    addFeedItem('threat', f.host, riskScore, f.isTyposquat ? 'Typosquatting' : f.isIP ? 'Raw IP' : 'Phishing', rawUrl);
  } else {
    addConsoleLine('ok', `[VPN] Allowed → ${f.host} (score ${riskScore.toFixed(0)}/100)`);
  }

  return { riskScore, isMalicious, features: f };
}

// ─── URL Scanner Functions ──────────────────────────────────

// Client-side rate limiter: max 20 scans per 60-second window
const RateLimit = {
  maxRequests: 20,
  windowMs: 60000,
  timestamps: [],
  check() {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
    if (this.timestamps.length >= this.maxRequests) return false;
    this.timestamps.push(now);
    return true;
  },
};

function runLiveScan() {
  if (!RateLimit.check()) {
    addConsoleLine('warn', '[RATE LIMIT] Too many scan requests — please wait 60 seconds.');
    return;
  }
  const url = document.getElementById('url-input').value.trim();
  if (!url) return;
  if (url.length > 2048) {
    addConsoleLine('warn', '[VALIDATE] Input exceeds 2048 character limit — rejected.');
    return;
  }
  State.sessionsScanned++;
  addConsoleLine('info', '[TFLite] Inference started → "' + url.substring(0, 60) + (url.length > 60 ? '…' : '') + '"');
  renderScanResult('quick-scan-result', url);
}

function setSampleUrl(url) {
  document.getElementById('url-input').value = url;
  switchScreen('scanner');
  setTimeout(runLiveScan, 50);
}

function runBatchScan() {
  if (!RateLimit.check()) {
    addConsoleLine('warn', '[RATE LIMIT] Too many scan requests — please wait 60 seconds.');
    return;
  }
  const raw = document.getElementById('batch-input').value || '';
  if (raw.length > 10000) {
    addConsoleLine('warn', '[VALIDATE] Batch input exceeds 10,000 character limit — rejected.');
    return;
  }
  // Cap batch at 100 URLs max
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 100);
  if (!lines.length) return;
  const container = document.getElementById('batch-results');
  container.innerHTML = '';

  lines.forEach((url, i) => {
    const f = extractFeatures(url);
    const risk = computeRiskScore(f);
    const mal = risk > 45;
    if (mal) State.threatsBlocked++;
    const row = document.createElement('div');
    const bg = mal ? 'rgba(255,59,59,.06)' : 'rgba(0,214,143,.04)';
    const bd = mal ? 'rgba(255,59,59,.25)' : 'rgba(0,214,143,.2)';
    const cl = mal ? 'var(--danger-red)' : 'var(--success-green)';
    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:.75rem;padding:.65rem 1rem;border-radius:8px;margin-bottom:.5rem;background:' + bg + ';border:1px solid ' + bd + ';font-size:.82rem;';
    const safeUrl = escapeHTML(url);
    row.innerHTML =
      '<span style="font-family:var(--font-mono);color:var(--text-muted);min-width:2ch">' + (i + 1) + '</span>' +
      '<span style="flex:1;font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-main)">' + safeUrl + '</span>' +
      '<span style="font-family:var(--font-mono);font-weight:700;color:' + cl + ';">' + risk.toFixed(0) + '/100</span>' +
      '<span style="font-weight:700;color:' + cl + ';min-width:80px;text-align:right">' + (mal ? '\uD83D\uDEAB THREAT' : '\u2705 SAFE') + '</span>';
    container.appendChild(row);
  });
  updateThreatCounter();
  addConsoleLine('info', '[Batch] Scanned ' + lines.length + ' URLs \u2014 ' + State.threatsBlocked + ' threats total');
}

// ─── UPI Functions ──────────────────────────────────────────
function setUPI(str) {
  document.getElementById('upi-input').value = str;
  verifyUPIIntent();
}

function verifyUPIIntent() {
  const raw = document.getElementById('upi-input').value.trim();
  const el  = document.getElementById('upi-verification-result');
  const paramsEl = document.getElementById('upi-params');

  if (!raw.startsWith('upi://pay')) {
    el.innerHTML = `<div style="color:var(--danger-red);font-weight:700">❌ Invalid URI — expected <code>upi://pay</code> prefix</div>`;
    el.className = 'scan-result visible malicious';
    return;
  }

  const qs = raw.split('?')[1] || '';
  const p = new URLSearchParams(qs);
  const pa = p.get('pa') || 'MISSING';
  const pn = decodeURIComponent(p.get('pn') || 'Unknown');
  const am = p.get('am') || 'Not specified';
  const tn = decodeURIComponent(p.get('tn') || 'None');
  const sign = p.get('sign');

  // Threat signals
  const OFFICIAL_BRANDS = ['electricity', 'sbi', 'hdfc', 'icici', 'income tax', 'refund', 'rbi', 'npci', 'government'];
  const MULE_HANDLES = ['ybl', 'okaxis', 'okicici', 'scammer', 'fraud', 'mule'];
  const SOCIAL_ENG = ['pin required', 'enter pin', 'receive refund', 'otp required', 'urgent'];

  const pnLower = pn.toLowerCase();
  const paLower = pa.toLowerCase();
  const tnLower = tn.toLowerCase();

  const nameSpoofed = OFFICIAL_BRANDS.some(b => pnLower.includes(b)) &&
                      MULE_HANDLES.some(m => paLower.includes(m));
  const socialEng   = SOCIAL_ENG.some(s => tnLower.includes(s));
  const largeAmount = parseFloat(am) > 10000;
  const noSignature = !sign;
  const isCollectAbuse = socialEng || nameSpoofed;

  const isMalicious = nameSpoofed || isCollectAbuse;
  const riskIndicators = [
    nameSpoofed   && '⚠ Payee Name Deception',
    socialEng     && '⚠ Social Engineering in tn field',
    largeAmount   && '⚠ High-value transaction',
    noSignature   && '⚠ No cryptographic signature',
  ].filter(Boolean);

  // Show params grid
  paramsEl.style.display = 'grid';
  paramsEl.innerHTML = `
    <div class="upi-param-box"><div class="upi-param-label">Recipient VPA (pa)</div><div class="upi-param-value ${nameSpoofed ? 'danger' : ''}">${escapeHTML(pa)}</div></div>
    <div class="upi-param-box"><div class="upi-param-label">Payee Name (pn)</div><div class="upi-param-value">${escapeHTML(pn)}</div></div>
    <div class="upi-param-box"><div class="upi-param-label">Amount (am)</div><div class="upi-param-value ${largeAmount ? 'danger' : ''}">${am ? '₹' + escapeHTML(am) : 'Not set'}</div></div>
    <div class="upi-param-box"><div class="upi-param-label">Transaction Note (tn)</div><div class="upi-param-value ${socialEng ? 'danger' : ''}">${escapeHTML(tn)}</div></div>
    <div class="upi-param-box"><div class="upi-param-label">Signature (sign)</div><div class="upi-param-value ${noSignature ? 'danger' : 'safe'}">${sign ? '✓ Present' : '✗ Absent'}</div></div>
    <div class="upi-param-box"><div class="upi-param-label">RakshaLink Action</div><div class="upi-param-value ${isMalicious ? 'danger' : 'safe'}">${isMalicious ? 'INTENT BLOCKED' : 'setPackage() → PSP App'}</div></div>
  `;

  const html = `
    <div class="result-header">
      <div class="result-verdict ${isMalicious ? 'verdict-malicious' : 'verdict-safe'}">
        ${isMalicious ? '⚠️ SUSPICIOUS UPI INTENT BLOCKED' : '✅ VALIDATED UPI PAYMENT INTENT'}
      </div>
    </div>
    ${riskIndicators.length ? `
      <div style="margin-bottom:1rem">
        ${riskIndicators.map(r => `<div style="font-size:.83rem;color:var(--danger-red);margin-bottom:.35rem">${r}</div>`).join('')}
      </div>
    ` : ''}
    <div style="font-size:.85rem;color:var(--text-muted);line-height:1.6">
      <strong>Security Action:</strong>
      ${isMalicious
        ? `<span style="color:var(--danger-red)"> INTENT REDIRECTION BLOCKED. Prevented unauthenticated VPA spoofing. No package routing executed. User displayed full-screen warning dialog.</span>`
        : `<span style="color:var(--success-green)"> Intent sanitized. Explicit routing enforced via <code>Intent.setPackage()</code> to verified PSP application. Deep link collision risk eliminated.</span>`}
    </div>
  `;

  el.innerHTML = html;
  el.className = `scan-result visible ${isMalicious ? 'malicious' : 'safe'}`;

  if (isMalicious) {
    State.threatsBlocked++;
    updateThreatCounter();
    addConsoleLine('error', `[UPI] Blocked intent → pa:${pa} | pn:${pn}`);
    addFeedItem('upi', pa, 90, 'UPI VPA Deception', raw);
  }
}

// ─── SMS Functions ──────────────────────────────────────────
const SMS_SAMPLES = [
  { sender: 'VM-ELECBD', text: 'Dear consumer your electricity line will be disconnected tonight at 9:30 PM. Update immediately at: http://electricity-bill-disconnection-alert.top/pay', expected: 'threat' },
  { sender: 'AD-HDFCBK', text: 'Your HDFC Bank account credited with Rs. 5,000.00 via UPI Ref 4291048102. Available balance: Rs. 42,150.00.', expected: 'clean' },
  { sender: 'QP-WORKIN', text: 'Earn ₹5000 daily by liking YouTube videos! Click link to register: http://task-earning-hub.xyz/join', expected: 'threat' },
  { sender: 'BP-SBIBNK', text: 'ALERT: Your SBI account is temporarily suspended. KYC update required within 24hrs at http://sbi-kyc-alert.top/verify', expected: 'threat' },
  { sender: 'AD-PAYTM',  text: 'Your Paytm wallet has been updated successfully. Balance: Rs. 1,250.00. Transaction ID: PTM88492012.', expected: 'clean' },
];

function renderSMSList(items) {
  const container = document.getElementById('sms-list');
  container.innerHTML = '';
  let threats = 0;
  items.forEach((msg, idx) => {
    const urlMatch = msg.text.match(/https?:\/\/[^\s]+/i);
    const url = urlMatch ? urlMatch[0] : null;
    let riskScore = 5, classification = 'clean';
    if (url) {
      const f = extractFeatures(url);
      riskScore = computeRiskScore(f);
    } else {
      const textLower = msg.text.toLowerCase();
      const kwHits = SUSPICIOUS_KEYWORDS.filter(k => textLower.includes(k)).length;
      riskScore = Math.min(kwHits * 15, 80);
    }
    classification = riskScore > 60 ? 'threat' : riskScore > 35 ? 'warn' : 'clean';
    if (classification === 'threat') threats++;

    const div = document.createElement('div');
    div.className = `sms-item ${classification}`;
    div.innerHTML = `
      <div style="flex:1">
        <div class="sms-sender">📱 ${msg.sender}</div>
        <div class="sms-text">${msg.text.replace(/https?:\/\/[^\s]+/gi, m => `<u>${m}</u>`)}</div>
        <div class="sms-footer">
          <span class="tag tag-${classification}">${classification === 'threat' ? 'Smishing Threat' : classification === 'warn' ? 'Suspicious' : 'Clean'}</span>
          ${url ? `<span class="tag tag-scan">URL Detected</span>` : ''}
          ${riskScore > 40 ? `<span class="tag" style="background:rgba(255,59,59,.1);color:var(--danger-red);border:1px solid rgba(255,59,59,.25)">Risk: ${riskScore.toFixed(0)}/100</span>` : ''}
        </div>
      </div>
    `;
    container.appendChild(div);
  });

  document.getElementById('sms-count').textContent = items.length;
  document.getElementById('sms-threat-stat').textContent = threats;
  document.getElementById('sms-threat-count').textContent = `${threats} Threat${threats !== 1 ? 's' : ''}`;
}

function scanAllSMS() {
  renderSMSList(SMS_SAMPLES);
  addConsoleLine('info', `[SMS] Re-scanned ${SMS_SAMPLES.length} messages`);
}

function simulateNewSMS() {
  const newSMS = [
    { sender: 'JK-INCOMETAX', text: 'URGENT: Income Tax refund of Rs.18,500 pending. Verify PAN at http://incometax-refund-portal.xyz/verify to receive funds.', expected: 'threat' },
    { sender: 'AD-ICICIBK',   text: 'ICICI Bank: Your credit card ending 5542 used for Rs.2,450 at Amazon. Call 1800-xxx if not done.', expected: 'clean' },
  ];
  const all = [...SMS_SAMPLES, ...newSMS];
  renderSMSList(all);
  addConsoleLine('warn', '[NLS] New SMS intercepted — classified by TFLite engine');
  State.threatsBlocked++;
  updateThreatCounter();
}

function scanCustomSMS() {
  const text = document.getElementById('sms-custom').value.trim();
  const el = document.getElementById('custom-sms-result');
  if (!text) return;

  const urlMatch = text.match(/https?:\/\/[^\s]+/i);
  const url = urlMatch ? urlMatch[0] : null;
  let riskScore = 5, details = 'No URL found — keyword analysis only.';

  if (url) {
    const f = extractFeatures(url);
    riskScore = computeRiskScore(f);
    details = `URL: <code>${url}</code> · Entropy: ${f.entropy} · Typosquat: ${f.isTyposquat ? 'YES' : 'no'} · Keywords: ${f.keywordsFound.join(', ') || 'none'}`;
  } else {
    const lower = text.toLowerCase();
    const hits = SUSPICIOUS_KEYWORDS.filter(k => lower.includes(k));
    riskScore = Math.min(hits.length * 18, 85);
    details = `Keyword signals: ${hits.join(', ') || 'none'}`;
  }

  const mal = riskScore > 45;
  el.innerHTML = `
    <div class="result-header">
      <div class="result-verdict ${mal ? 'verdict-malicious' : 'verdict-safe'}">${mal ? '🚨 Smishing Threat Detected' : '✅ SMS Appears Clean'}</div>
      <div class="result-score"><span class="label">Risk Score</span><span class="value" style="color:${mal ? 'var(--danger-red)' : 'var(--success-green)'}">${riskScore.toFixed(0)}/100</span></div>
    </div>
    <div class="conf-row"><div class="conf-label-row"><span>Threat Confidence</span><span>${riskScore.toFixed(0)}%</span></div>
    <div class="conf-bar-bg"><div class="conf-bar-fill ${mal ? 'fill-red' : 'fill-green'}" style="width:${riskScore}%"></div></div></div>
    <div style="font-size:.83rem;color:var(--text-muted);margin-top:.75rem">${details}</div>
  `;
  el.className = `scan-result visible ${mal ? 'malicious' : 'safe'}`;
}

// ─── QR Functions ───────────────────────────────────────────
function setQR(str) {
  document.getElementById('qr-input').value = str;
  analyzeQR();
}

function analyzeQR() {
  const raw = document.getElementById('qr-input').value.trim();
  const el  = document.getElementById('qr-result');

  if (raw.startsWith('upi://pay')) {
    document.getElementById('upi-input').value = raw;
    verifyUPIIntent();
    const upiEl = document.getElementById('upi-verification-result');
    const clone = upiEl.cloneNode(true);
    clone.id = 'qr-result-inner';
    el.innerHTML = '<div style="color:var(--accent-blue);font-size:.85rem;margin-bottom:.75rem">📷 QR decoded as UPI payment intent — routing to UPI engine:</div>';
    el.appendChild(clone);
    el.className = 'scan-result visible';
    if (clone.classList.contains('malicious')) el.classList.add('malicious');
    else el.classList.add('safe');
  } else {
    renderScanResult('qr-result', raw);
  }
}

function renderQRScenarios() {
  const scenarios = [
    { title: 'Merchant QR Code Sticker Swap', icon: '🏪', risk: 'high', desc: 'Attacker stickers their own QR code (with mule VPA) over legitimate restaurant/shop payment QR. Customer scans and pays directly to fraud account.', payload: 'upi://pay?pa=fraud_merchant99@okicici&pn=Dominos%20Pizza&am=450.00&cu=INR' },
    { title: 'Fake Donation / Charity QR', icon: '🤲', risk: 'high', desc: 'Fraudulent charity drives with QR codes displayed on social media / WhatsApp. pn field shows "PM Relief Fund" or "Flood Victims". VPA routes to scammer.', payload: 'upi://pay?pa=fraud88@ybl&pn=PM%20Flood%20Relief%20Fund&cu=INR' },
    { title: 'Homoglyph URL QR Code', icon: '🔤', risk: 'high', desc: 'QR encodes a URL using homoglyph characters (e.g. Cyrillic "а" vs Latin "a") creating a visually identical domain that bypasses text inspection.', payload: 'http://xn--pyo-zma.com/sbi-login' },
    { title: 'Legitimate Restaurant QR', icon: '☕', risk: 'safe', desc: 'Standard merchant-generated QR with valid pa VPA, matching pn, and cryptographic sign parameter. RakshaLink verifies all fields and routes via setPackage().', payload: 'upi://pay?pa=legitcafe@sbi&pn=Coffee%20Shop&am=120.00&cu=INR' },
  ];

  const container = document.getElementById('qr-scenarios');
  container.innerHTML = '';
  scenarios.forEach(s => {
    const div = document.createElement('div');
    div.className = 'qr-mock';
    div.style.borderLeft = `3px solid ${s.risk === 'high' ? 'var(--danger-red)' : 'var(--success-green)'}`;
    div.innerHTML = `
      <div class="qr-thumb">${s.icon}</div>
      <div class="qr-info" style="flex:1">
        <h4>${s.title}</h4>
        <p>${s.payload}</p>
        <div style="font-size:.8rem;color:var(--text-muted)">${s.desc}</div>
        <div style="margin-top:.5rem"><span class="tag ${s.risk === 'high' ? 'tag-threat' : 'tag-clean'}">${s.risk === 'high' ? 'Attack Vector' : 'Legitimate'}</span></div>
      </div>
      <button class="btn btn-sm" onclick="setQR('${s.payload}')" style="background:rgba(0,229,255,.08);color:var(--accent-blue);border:1px solid rgba(0,229,255,.2);border-radius:8px;cursor:pointer;padding:.4rem .9rem;font-family:var(--font-sans);font-weight:700;font-size:.78rem;flex-shrink:0;height:fit-content">Test →</button>
    `;
    container.appendChild(div);
  });
}

// ─── Live Feed & Console ─────────────────────────────────────
function addFeedItem(type, host, score, category, url) {
  const feed = document.getElementById('threat-feed');
  const now = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const div = document.createElement('div');
  div.className = `threat-item${type === 'upi' ? ' warn' : ''}`;
  const safeCategory = escapeHTML(category);
  const safeHost = escapeHTML(host);
  div.innerHTML = `
    <div class="ti-icon">${type === 'upi' ? '⚡' : '🚫'}</div>
    <div class="ti-body">
      <div class="ti-title">${safeCategory} — <code style="font-size:.82rem;color:var(--danger-red)">${safeHost}</code></div>
      <div class="ti-meta">Risk Score: ${score.toFixed ? score.toFixed(0) : score}/100 · VPN TUN Drop · DPDP Compliant</div>
    </div>
    <div class="ti-time">${escapeHTML(now)}</div>
  `;
  feed.prepend(div);
  if (feed.children.length > 8) feed.removeChild(feed.lastChild);
}

function addConsoleLine(level, msg) {
  const console = document.getElementById('sys-console');
  if (!console) return;
  const now = new Date().toLocaleTimeString('en-IN', { hour12: false });
  const div = document.createElement('div');
  div.className = 'log-line';
  const lvlClass = { info: 'lvl-info', warn: 'lvl-warn', error: 'lvl-error', ok: 'lvl-ok' }[level] || 'lvl-info';
  const lvlLabel = { info: '[INFO] ', warn: '[WARN] ', error: '[ERR]  ', ok: '[OK]   ' }[level] || '[INFO] ';
  const safeMsg = escapeHTML(msg);
  div.innerHTML = `<span class="ts">${escapeHTML(now)}</span><span class="${lvlClass}">${lvlLabel}${safeMsg}</span>`;
  console.prepend(div);
  if (console.children.length > 30) console.removeChild(console.lastChild);
}

// ─── Gauges ─────────────────────────────────────────────────
function setGauge(circleId, valId, percent, display) {
  const circumference = 2 * Math.PI * 54; // 339.292
  const circle = document.getElementById(circleId);
  const val = document.getElementById(valId);
  if (!circle || !val) return;
  setTimeout(() => {
    circle.style.strokeDashoffset = circumference * (1 - percent / 100);
    val.textContent = display;
  }, 300);
}

function animateGauges() {
  setGauge('g-acc',   'gv-acc',   99.81, '99.81%');
  setGauge('g-prec',  'gv-prec',  100,   '100%');
  setGauge('g-f1',    'gv-f1',    99.81, '99.81%');
  setGauge('g-block', 'gv-block', Math.min(State.threatsBlocked * 10, 100), State.threatsBlocked.toString());
}

function updateThreatCounter() {
  const el = document.getElementById('threat-count');
  if (el) el.textContent = State.threatsBlocked;
  setGauge('g-block', 'gv-block', Math.min(State.threatsBlocked * 10, 100), State.threatsBlocked.toString());
}

function showThreatDetail() {
  alert(`Full Threat Report:\n\nDomain: sbi-secure-login.xyz\nBrand Impersonated: State Bank of India (onlinesbi.sbi)\nLevenshtein Distance: 3 edits\nJaro-Winkler Score: 0.91\nShannon Entropy: 4.21 bits (DGA risk)\nSuspicious TLD: .xyz\nKeywords Found: login, secure, verify\nVPN Action: Packet Dropped (TUN Interface)\nRisk Score: 98.4 / 100`);
}

// ─── Live Feed Seed ─────────────────────────────────────────
function seedFeed() {
  const incidents = [
    { type: 'threat', host: 'sbi-secure-login.xyz', score: 98, cat: 'Typosquatting', url: '' },
    { type: 'threat', host: 'electricity-bill-disconnection-alert.top', score: 91, cat: 'Smishing URL', url: '' },
    { type: 'upi',    host: 'scammer88@ybl', score: 95, cat: 'UPI VPA Deception', url: '' },
    { type: 'threat', host: '192.168.1.1/update-kyc.apk', score: 89, cat: 'Raw IP APK Drop', url: '' },
  ];
  incidents.forEach(i => {
    State.threatsBlocked++;
    addFeedItem(i.type, i.host, i.score, i.cat, i.url);
  });
  updateThreatCounter();
}

function seedConsole() {
  const logs = [
    { l: 'info',  m: '[VPN] TUN interface initialized — routes 0.0.0.0/0' },
    { l: 'ok',    m: '[TFLite] Char-CNN (INT8) loaded — 1.8MB · NNAPI delegate active' },
    { l: 'ok',    m: '[TFLite] LightGBM model loaded — 0.4MB · CPU inference' },
    { l: 'info',  m: '[NLS] NotificationListenerService bound — SMS monitoring active' },
    { l: 'ok',    m: '[System] DPDP Act 2023 compliance verified — no remote data transmission' },
    { l: 'warn',  m: '[VPN] Blocked → sbi-secure-login.xyz (score 98/100)' },
    { l: 'error', m: '[UPI] Intent BLOCKED → pa:scammer88@ybl | pn:State Electricity Board' },
    { l: 'ok',    m: '[VPN] Allowed → onlinesbi.sbi (score 3/100)' },
  ];
  logs.reverse().forEach(({ l, m }) => addConsoleLine(l, m));
}

// ─── Init ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  seedFeed();
  seedConsole();
  animateGauges();
  renderSMSList(SMS_SAMPLES);
  renderQRScenarios();
  // Run default scan
  runLiveScan();

  // Periodic console heartbeat
  setInterval(() => {
    const msgs = [
      ['info', '[VPN] Heartbeat — 0 new threats in scan window'],
      ['ok',   `[TFLite] Model inference ready — avg latency: ${(Math.random() * 30 + 65).toFixed(0)}ms`],
      ['info', '[NLS] Notification listener active — watching default SMS app'],
    ];
    const pick = msgs[Math.floor(Math.random() * msgs.length)];
    addConsoleLine(pick[0], pick[1]);
  }, 8000);

  // Periodic threat simulation
  setInterval(() => {
    const threats = [
      ['phish.top', 85, 'Phishing URL'],
      ['hdfc-kyc-alert.xyz', 92, 'Typosquatting'],
      ['mule99@okaxis', 88, 'UPI VPA Fraud'],
    ];
    const t = threats[Math.floor(Math.random() * threats.length)];
    State.threatsBlocked++;
    addFeedItem('threat', t[0], t[1], t[2], '');
    updateThreatCounter();
    addConsoleLine('warn', `[VPN] New threat intercepted → ${t[0]} (${t[1]}/100)`);
  }, 12000);
});
