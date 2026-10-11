(function (global) {
  function escapeHTML(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
    for (let i = 1; i <= m; i++)
      for (let j = 1; j <= n; j++)
        dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
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

  function normalizeUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return '';
    const trimmed = rawUrl.trim();
    if (!trimmed) return '';
    if (/^(https?:)?\/\//i.test(trimmed)) return trimmed;
    return `http://${trimmed}`;
  }

  function extractFeatures(rawUrl) {
    const normalizedValue = normalizeUrl(rawUrl);
    let host = '', path = '', tld = '', isIP = false, hasHttps = false;
    try {
      const parsed = new URL(normalizedValue);
      host = parsed.hostname.toLowerCase();
      path = parsed.pathname + parsed.search;
      hasHttps = parsed.protocol === 'https:';
      isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
      const parts = host.split('.');
      tld = parts.length >= 2 ? '.' + parts.slice(-1)[0] : '';
    } catch {
      host = normalizedValue.split('/')[0].toLowerCase();
    }

    const entropy = shannonEntropy(host);
    const hasAt = (rawUrl || '').includes('@');
    const dotCount = ((normalizedValue || '').match(/\./g) || []).length;
    const hyphenCount = (host.match(/-/g) || []).length;
    const urlLen = (normalizedValue || '').length;
    const keywordsFound = SUSPICIOUS_KEYWORDS.filter(k => (normalizedValue || '').toLowerCase().includes(k));
    const suspiciousTLD = SUSPICIOUS_TLDS.some(t => host.endsWith(t) || (normalizedValue || '').endsWith(t));

    let minDist = Infinity, bestBrand = '', bestJaro = 0;
    for (const brand of PROTECTED_BRANDS) {
      const dist = levenshtein(host, brand);
      if (dist < minDist) {
        minDist = dist;
        bestBrand = brand;
        bestJaro = jaroWinkler(host, brand);
      }
    }
    const isExactLegit = minDist === 0;
    const brandImpersonation = !isExactLegit && PROTECTED_BRANDS.some((brand) => {
      const brandLabel = brand.split('.')[0];
      const normalizedHost = host.replace(/-/g, '');
      return normalizedHost.includes(brandLabel) && normalizedHost !== brandLabel;
    });
    const isTyposquat = (minDist > 0 && minDist <= 6 && bestJaro > 0.7) || brandImpersonation;

    return {
      host, path, tld, hasHttps, isIP, hasAt,
      dotCount, hyphenCount, urlLen, entropy,
      keywordsFound, suspiciousTLD,
      minDist, bestBrand, bestJaro: +bestJaro.toFixed(3),
      isTyposquat, isExactLegit, brandImpersonation,
    };
  }

  function computeRiskScore(f) {
    if (f.isExactLegit) return 3;
    let score = 0;

    if (f.urlLen > 50) score += 10;
    if (f.urlLen > 80) score += 8;
    if (f.dotCount >= 3) score += 15;
    if (f.hyphenCount >= 2) score += 12;
    if (f.hasAt) score += 30;

    if (!f.hasHttps) score += 8;
    if (f.isIP) score += 35;

    if (f.entropy > 3.6) score += 15;
    if (f.entropy > 4.0) score += 10;

    if (f.suspiciousTLD) score += 25;
    score += Math.min(f.keywordsFound.length * 12, 40);

    if (f.isTyposquat) score += Math.max(0, (6 - f.minDist) * 8);
    if (f.brandImpersonation) score += 25;

    return Math.min(Math.max(score, 2), 99.5);
  }

  function safeDecodeURIComponent(value, fallback = 'Unknown') {
    if (value == null || value === '') return fallback;
    try {
      return decodeURIComponent(String(value));
    } catch {
      return String(value);
    }
  }

  function analyzeUPIIntent(raw) {
    const text = typeof raw === 'string' ? raw.trim() : '';
    if (!text || !text.startsWith('upi://pay')) {
      return {
        isValid: false,
        isMalicious: false,
        riskIndicators: [],
        details: { pa: 'MISSING', pn: 'Unknown', am: 'Not specified', tn: 'None', sign: null },
      };
    }

    const qs = text.split('?')[1] || '';
    const params = new URLSearchParams(qs);
    const pa = safeDecodeURIComponent(params.get('pa'), 'MISSING');
    const pn = safeDecodeURIComponent(params.get('pn'), 'Unknown');
    const am = params.get('am') || 'Not specified';
    const tn = safeDecodeURIComponent(params.get('tn'), 'None');
    const sign = params.get('sign');

    const OFFICIAL_BRANDS = ['electricity', 'sbi', 'hdfc', 'icici', 'income tax', 'refund', 'rbi', 'npci', 'government'];
    const MULE_HANDLES = ['ybl', 'okaxis', 'okicici', 'scammer', 'fraud', 'mule'];
    const SOCIAL_ENG = ['pin required', 'enter pin', 'receive refund', 'otp required', 'urgent'];

    const pnLower = pn.toLowerCase();
    const paLower = pa.toLowerCase();
    const tnLower = tn.toLowerCase();

    const nameSpoofed = OFFICIAL_BRANDS.some(b => pnLower.includes(b)) && MULE_HANDLES.some(m => paLower.includes(m));
    const socialEng = SOCIAL_ENG.some(s => tnLower.includes(s));
    const largeAmount = parseFloat(am) > 10000;
    const noSignature = !sign;
    const isCollectAbuse = socialEng || nameSpoofed;
    const isMalicious = nameSpoofed || isCollectAbuse;

    const riskIndicators = [
      nameSpoofed && 'Payee Name Deception',
      socialEng && 'Social Engineering in tn field',
      largeAmount && 'High-value transaction',
      noSignature && 'No cryptographic signature',
    ].filter(Boolean);

    return {
      isValid: true,
      isMalicious,
      riskIndicators,
      details: { pa, pn, am, tn, sign },
    };
  }

  const exported = {
    escapeHTML,
    levenshtein,
    jaroWinkler,
    shannonEntropy,
    PROTECTED_BRANDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    normalizeUrl,
    extractFeatures,
    computeRiskScore,
    safeDecodeURIComponent,
    analyzeUPIIntent,
  };

  if (typeof module !== 'undefined') module.exports = exported;
  global.RakshaLinkCore = exported;
})(typeof globalThis !== 'undefined' ? globalThis : this);
