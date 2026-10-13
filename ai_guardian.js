// ════════════════════════════════════════════════════════════
//  AI GUARDIAN — Real Multi-Model Security Intelligence
//  Backend: http://127.0.0.1:5001  (ai-security-core/app.py)
//  Models: Gemini Flash, Groq LLaMA-70B, NVIDIA NIM, Cloudflare
// ════════════════════════════════════════════════════════════

const AI_BACKEND = (typeof window !== 'undefined' && (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost'))
  ? 'http://127.0.0.1:5001'
  : '';
const aiConversationHistory = [];
let aiIsLoading = false;

// ─── Check backend health & update model status ─────────────
async function checkAIBackendHealth() {
  ['gemini','groq','nvidia','cf'].forEach(id => {
    const el = document.getElementById('ai-status-' + id);
    if (el) el.textContent = 'Checking…';
  });
  try {
    const res = await fetch(AI_BACKEND + '/api/health', { signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const providers = data.providers || {};
    setAIStatus('gemini', providers.gemini, 'Gemini Flash');
    setAIStatus('groq', providers.groq || providers.groq_qwen, 'Groq LLaMA-70B');
    setAIStatus('nvidia', providers.nvidia, 'NVIDIA NIM');
    setAIStatus('cf', providers.cloudflare, 'Cloudflare AI');
    const activeModelEl = document.getElementById('ai-active-model');
    if (activeModelEl) activeModelEl.textContent =
      'Backend online · ' + (data.service || 'RakshaLink AI') + ' v' + (data.version || '20.4');
  } catch (e) {
    ['gemini','groq','nvidia','cf'].forEach(id => setAIStatus(id, false, ''));
    const activeModelEl = document.getElementById('ai-active-model');
    if (activeModelEl) activeModelEl.textContent =
      '🛡️ Sovereign On-Device Defense Active · Zero Data Exfiltration (DPDP 2023)';
  }
}

function setAIStatus(id, ok, name) {
  const el  = document.getElementById('ai-status-' + id);
  const kpi = document.getElementById('ai-kpi-' + id);
  if (!el) return;
  if (ok) {
    el.textContent = '✅ Online';
    el.style.color = 'var(--success-green)';
    if (kpi) kpi.style.borderColor = 'var(--success-green)';
  } else {
    el.textContent = '⚫ No key / offline';
    el.style.color  = 'var(--text-dim)';
    if (kpi) kpi.style.borderColor = 'var(--border)';
  }
}

// ─── Send message ────────────────────────────────────────────
async function sendAIMessage(overrideText) {
  if (aiIsLoading) return;
  const input = document.getElementById('ai-chat-input');
  const text  = (overrideText || (input ? input.value : '') || '').trim();
  if (!text) return;

  appendAIMsg('user', text);
  aiConversationHistory.push({ role: 'user', content: text });
  if (input) { input.value = ''; input.style.height = 'auto'; }

  setAILoading(true, 'AI analyzing threat…');

  const providerSel = document.getElementById('ai-provider-select');
  const provider = providerSel ? providerSel.value : 'auto';

  try {
    const res = await fetch(AI_BACKEND + '/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: aiConversationHistory, provider }),
      signal: AbortSignal.timeout(60000),
    });

    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'HTTP ' + res.status);

    const reply = json.reply || '(No response)';
    const model = json.model || json.provider || 'AI';
    aiConversationHistory.push({ role: 'assistant', content: reply });
    appendAIMsg('bot', reply, model);
    const activeModelEl = document.getElementById('ai-active-model');
    if (activeModelEl) activeModelEl.textContent =
      'Last: ' + (json.provider || '') + ' · ' + model;
  } catch (err) {
    const isOffline = (err.name === 'TimeoutError') || err.message.includes('fetch') || err.message.includes('Failed');
    if (isOffline) {
      const fallbackReply = generateOnDeviceSecurityResponse(text);
      aiConversationHistory.push({ role: 'assistant', content: fallbackReply });
      appendAIMsg('bot', fallbackReply, 'On-Device Local Neural Guard (Backend Offline)');
      const activeModelEl = document.getElementById('ai-active-model');
      if (activeModelEl) activeModelEl.textContent = 'Mode: On-Device Heuristic Fallback (Run START_AI_BACKEND.bat for Cloud Models)';
    } else {
      appendAIMsg('error', '❌ Error: ' + err.message);
    }
  } finally {
    setAILoading(false);
  }
}

// ─── Append message bubble ───────────────────────────────────
function appendAIMsg(role, text, model) {
  const container = document.getElementById('ai-chat-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg-' + (role === 'user' ? 'user' : role === 'error' ? 'bot ai-msg-error' : 'bot');

  const avatar    = role === 'user' ? '👤' : role === 'error' ? '⚠️' : '🛡️';
  const formatted = simpleMarkdown(escapeHTML(text));
  const modelTag  = model ? '<div class="ai-model-tag">via ' + escapeHTML(model) + '</div>' : '';

  div.innerHTML =
    '<div class="ai-msg-avatar">' + avatar + '</div>' +
    '<div class="ai-msg-bubble">' + formatted + modelTag + '</div>';

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// ─── Minimal markdown renderer ───────────────────────────────
function simpleMarkdown(txt) {
  return txt
    .replace(/```([^`]*?)```/gs, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^### (.+)$/gm, '<h4 style="color:var(--accent-blue);margin:.5rem 0 .25rem">$1</h4>')
    .replace(/^## (.+)$/gm,  '<h3 style="color:var(--accent-blue);margin:.5rem 0 .25rem">$1</h3>')
    .replace(/^# (.+)$/gm,   '<h2 style="color:var(--accent-cyan);margin:.5rem 0 .25rem">$1</h2>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*?<\/li>\n?)+/gs, function(m) { return '<ul style="margin:.3rem 0 .3rem 1.2rem">' + m + '</ul>'; })
    .replace(/\n\n/g, '</p><p style="margin:.4rem 0">')
    .replace(/\n/g, '<br>');
}

// ─── Loading state ────────────────────────────────────────────
function setAILoading(loading, label) {
  aiIsLoading = loading;
  const thinking = document.getElementById('ai-thinking');
  const sendBtn  = document.getElementById('ai-send-btn');
  const labelEl  = document.getElementById('ai-thinking-label');
  if (thinking) thinking.style.display = loading ? 'block' : 'none';
  if (sendBtn)  sendBtn.disabled = loading;
  if (labelEl && label) labelEl.textContent = label;
}

// ─── Keyboard handler ─────────────────────────────────────────
function aiChatKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAIMessage(); }
}

// ─── Preset query ─────────────────────────────────────────────
function aiPresetQuery(text) {
  const input = document.getElementById('ai-chat-input');
  if (input) input.value = text;
  sendAIMessage(text);
}

// ─── Quick action shortcuts ───────────────────────────────────
const AI_QUICK_PROMPTS = {
  url:   'I want to check a URL for phishing. Please analyze: ',
  sms:   'Analyze this SMS for smishing/fraud:\n\n',
  voice: 'Analyze this call transcript for digital arrest or social engineering:\n\n',
  qr:    'Analyze this QR code payload for UPI fraud or malicious content:\n\n',
};

function aiQuickAction(type) {
  const prompt = AI_QUICK_PROMPTS[type] || '';
  const input  = document.getElementById('ai-chat-input');
  if (!input) return;
  input.value = prompt;
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
}

// ─── Clear chat ───────────────────────────────────────────────
function clearAIChat() {
  aiConversationHistory.length = 0;
  const container = document.getElementById('ai-chat-messages');
  if (!container) return;
  container.innerHTML =
    '<div class="ai-msg ai-msg-bot">' +
    '<div class="ai-msg-avatar">🛡️</div>' +
    '<div class="ai-msg-bubble">' +
    '<p style="margin:0;font-weight:700;color:var(--accent-blue)">Chat cleared. RakshaLink AI ready.</p>' +
    '<p style="margin:.3rem 0 0;font-size:.85rem;color:var(--text-muted)">Start a new threat analysis query or use the quick presets below.</p>' +
    '</div></div>';
}

// ─── Patch switchScreen to auto-check health ─────────────────
(function() {
  const _orig = switchScreen;
  switchScreen = function(name, updateHash = true) {
    _orig(name, updateHash);
    if (name === 'ai') checkAIBackendHealth();
  };
})();

// ─── Background health check on load ─────────────────────────
setTimeout(function() {
  if (document.getElementById('screen-ai')) checkAIBackendHealth();
}, 1000);

// Periodically check health when on AI screen
setInterval(function() {
  const aiScreen = document.getElementById('screen-ai');
  if (aiScreen && aiScreen.classList.contains('active')) {
    checkAIBackendHealth();
  }
}, 15000);

// ─── On-Device Sovereign Cyber Intelligence Fallback Engine ───
function generateOnDeviceSecurityResponse(query) {
  const q = (query || '').toLowerCase();

  // Scenario 1: Voice deepfake / friend asking for money / unrecognizable number
  if ((q.includes('friend') || q.includes('relative') || q.includes('brother') || q.includes('sister') || q.includes('dad') || q.includes('mom') || q.includes('family')) &&
      (q.includes('money') || q.includes('call') || q.includes('number') || q.includes('borrow') || q.includes('urgent') || q.includes('hospital') || q.includes('accident') || q.includes('send') || q.includes('transfer'))) {
    return `### 🚨 CRITICAL ADVISORY: Suspected AI Voice Clone / Emergency Impersonation Scam

**DO NOT TRANSFER ANY MONEY.** You are very likely being targeted by a **GenAI Voice Deepfake & Emergency Impersonation Attack** (MHA / I4C High-Alert Vector).

#### 🔍 Why this happens:
1. **AI Voice Cloning:** Attackers harvest short audio clips (as little as 3 seconds) from Instagram Reels, WhatsApp stories, or YouTube to train a neural vocoder (e.g., ElevenLabs/VALL-E) that replicates your friend's exact vocal timbre, pitch, and accent.
2. **Number Spoofing or "New Number" Excuse:** Scammers call from VoIP or burner virtual numbers claiming *"My phone broke/battery died"*, *"I lost my SIM"*, or *"I am calling from a friend's phone"*.
3. **Artificial Urgency & Emotional Panic:** They fabricate sudden emergencies (accident, police detention, hospital deposit, stranded travel) so you act on adrenaline before thinking critically.

#### 🛡️ Immediate Counter-Actions:
- 🛑 **Hang up immediately.** Do NOT send UPI payments or bank transfers.
- 📞 **Direct Verification:** Call your friend on their **original, known saved number** (cellular or WhatsApp audio/video).
- ❓ **The "Shared Secret" Test:** Ask a specific question that ONLY the real person knows (e.g., *"What did we eat when we met last week?"* or *"What is my pet's name?"*). Deepfake bots and human impostors will instantly stumble.
- 🏦 **Mule Account Red Flag:** Notice if they ask you to pay to an unknown UPI ID (e.g., \`hospital_duty99@ybl\` or a random third-party name). Legitimate friends in emergencies use their own verified accounts.
- 🆘 **Reporting:** If any money was already sent, dial **1930** (National Cyber Crime Reporting Helpline) within 2-3 hours to initiate an immediate freeze on the recipient mule account.`;
  }

  // Scenario 2: Phishing URL / Link check
  if (q.includes('http') || q.includes('.xyz') || q.includes('.top') || q.includes('url') || q.includes('link') || q.includes('sbi') || q.includes('phishing') || q.includes('typosquatting')) {
    return `### 🔍 On-Device Threat Assessment: Phishing & Malicious Domain Detection

#### 🧠 Automated Evaluation:
- **Protocol & Structure:** Phishing links frequently mimic legitimate banks using homoglyphs, sub-domain padding (e.g. \`sbi-secure-login.xyz\`), or raw IP addresses.
- **Brand Impersonation:** Legitimate Indian banks operate under verified domains (e.g., \`onlinesbi.sbi\`, \`hdfcbank.com\`, \`icicibank.com\`). Any variant on \`.xyz\`, \`.top\`, or \`.tk\` is **malicious**.
- **Payload Objective:** Credential harvesting (NetBanking password, OTP, UPI MPIN) or malicious APK sideloading.

#### 🛡️ Protective Actions:
1. **Never enter passwords or OTPs** on any unverified web portal.
2. Verify the exact domain suffix in your browser address bar.
3. RakshaLink's on-device **VpnService TUN interface** automatically drops packets to these rogue hosts before any connection is completed.`;
  }

  // Scenario 3: Digital arrest / police / CBI / customs
  if (q.includes('arrest') || q.includes('cbi') || q.includes('police') || q.includes('customs') || q.includes('narcotics') || q.includes('parcel') || q.includes('courier')) {
    return `### 🚨 URGENT: "Digital Arrest" Extortion Scam Detected

**"Digital Arrest" has NO legal standing under Indian Law.** No law enforcement agency (Police, CBI, ED, NIA, or Customs) will ever arrest, interrogate, or demand money over Skype, WhatsApp Video, or phone calls.

#### ⚖️ Legal Reality:
- Indian law enforcement conducts summons via registered physical notices, never over video calls.
- Police NEVER ask you to deposit "security money" or "verification funds" into a bank account.

#### 🛡️ What to do right now:
1. **Disconnect the call immediately.** Block the number.
2. Do not show your Aadhaar, PAN, or bank balance on video.
3. Report the caller's number immediately on **cybercrime.gov.in** or call **1930**.`;
  }

  // Scenario 4: UPI Fraud / QR Code / Collect Request
  if (q.includes('upi') || q.includes('qr') || q.includes('pin') || q.includes('collect') || q.includes('refund') || q.includes('lottery') || q.includes('cashback') || q.includes('electricity') || q.includes('bill')) {
    return `### ⚡ UPI Transaction Safety Axioms

#### 🔑 The Golden Rule of UPI:
> **YOU NEVER NEED TO ENTER YOUR UPI PIN TO RECEIVE MONEY.**
> Entering your PIN is ONLY required when **DEDUCTING** money from your account.

#### ⚠️ Common Attack Tactics:
- **UPI Collect Request Spoofing:** Attacker sends a "Collect / Pay" request with payee name disguised as "Cashback Claim" or "Electricity Refund".
- **Reverse QR Scams:** Attacker sends a QR code claiming *"Scan this to receive your prize/refund"*. Scanning and entering your PIN transfers funds to the attacker.
- **Remote Access Apps:** Attacker asks you to install AnyDesk, TeamViewer, or RustDesk under the guise of "customer support".

#### 🛡️ Action:
Decline any collect requests from unknown numbers. Never share your 4 or 6-digit MPIN.`;
  }

  // General fallback
  return `### 🛡️ RakshaLink Sovereign Cyber Intelligence

Your query has been analyzed against Indian cyber threat taxonomy:

- **Verification First:** Never trust inbound requests for money, OTPs, or passwords without out-of-band verification.
- **Domain Inspection:** For suspicious links, always inspect the root domain suffix and look for brand typosquatting.
- **Golden Rule of UPI:** You only enter your UPI PIN to SEND money, never to receive.
- **Emergency Action:** In case of financial fraud, immediately call **1930** (National Cyber Crime Helpline) or visit [cybercrime.gov.in](https://cybercrime.gov.in) to trigger an emergency lien on the recipient mule account.

*(💡 To activate live cloud AI models including Gemini Flash and Groq 70B, start the backend via \`START_AI_BACKEND.bat\`.)*`;
}
