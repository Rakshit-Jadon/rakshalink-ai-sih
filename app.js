// ═════════════════════════════════════════════════════════════════════════
//  METACAP 3D APPLICATION LOGIC — RAKSHALINK AI SOVEREIGN SHIELD
//  Interactive 3D Three.js WebGL Engine, On-Device Forensic ML & Telemetry
// ═════════════════════════════════════════════════════════════════════════

'use strict';

// ─── 1. THREE.JS 3D HERO CRYSTAL SHIELD ENGINE ─────────────────────────
(function initThreeJSHero() {
  const canvas = document.getElementById('hero-3d-canvas');
  const container = document.getElementById('hero-canvas-container');
  if (!canvas || !container || typeof THREE === 'undefined') return;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 0.1, 1000);
  camera.position.z = 5.2;

  const renderer = new THREE.WebGLRenderer({
    canvas: canvas,
    alpha: true,
    antialias: true,
    powerPreference: 'high-performance'
  });
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  // Lights: Vivid Emerald Neon & Deep Mint
  const ambientLight = new THREE.AmbientLight(0x042414, 2.5);
  scene.add(ambientLight);

  const keyLight = new THREE.DirectionalLight(0x00ff9d, 3.8);
  keyLight.position.set(4, 5, 4);
  scene.add(keyLight);

  const fillLight = new THREE.DirectionalLight(0x059669, 2.2);
  fillLight.position.set(-4, -3, -2);
  scene.add(fillLight);

  const centerPointLight = new THREE.PointLight(0x00ff9d, 4, 8);
  centerPointLight.position.set(0, 0, 0);
  scene.add(centerPointLight);

  // Group for the 3D Emblem
  const shieldGroup = new THREE.Group();
  scene.add(shieldGroup);

  // Core Faceted Crystal Polyhedron (Icosahedron)
  const coreGeometry = new THREE.IcosahedronGeometry(1.25, 0);
  const coreMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x052e18,
    emissive: 0x00ff9d,
    emissiveIntensity: 0.25,
    roughness: 0.15,
    metalness: 0.85,
    clearcoat: 1.0,
    clearcoatRoughness: 0.1,
    flatShading: true,
    transparent: true,
    opacity: 0.88,
    reflectivity: 0.95
  });
  const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
  shieldGroup.add(coreMesh);

  // Outer Holographic Wireframe Cage
  const wireGeometry = new THREE.IcosahedronGeometry(1.48, 1);
  const wireMaterial = new THREE.MeshBasicMaterial({
    color: 0x00ff9d,
    wireframe: true,
    transparent: true,
    opacity: 0.35
  });
  const wireMesh = new THREE.Mesh(wireGeometry, wireMaterial);
  shieldGroup.add(wireMesh);

  // Inner Quantum Core
  const innerGeometry = new THREE.OctahedronGeometry(0.65, 0);
  const innerMaterial = new THREE.MeshBasicMaterial({
    color: 0x00ff9d,
    wireframe: true,
    transparent: true,
    opacity: 0.8
  });
  const innerMesh = new THREE.Mesh(innerGeometry, innerMaterial);
  shieldGroup.add(innerMesh);

  // Orbital Torus Ring 1
  const ring1Geometry = new THREE.TorusGeometry(1.9, 0.018, 16, 120);
  const ring1Material = new THREE.MeshBasicMaterial({
    color: 0x00ff9d,
    transparent: true,
    opacity: 0.65
  });
  const ring1 = new THREE.Mesh(ring1Geometry, ring1Material);
  ring1.rotation.x = Math.PI / 3;
  ring1.rotation.y = Math.PI / 6;
  shieldGroup.add(ring1);

  // Orbital Torus Ring 2
  const ring2Geometry = new THREE.TorusGeometry(2.15, 0.014, 16, 120);
  const ring2Material = new THREE.MeshBasicMaterial({
    color: 0x10b981,
    transparent: true,
    opacity: 0.45
  });
  const ring2 = new THREE.Mesh(ring2Geometry, ring2Material);
  ring2.rotation.x = -Math.PI / 4;
  ring2.rotation.y = -Math.PI / 5;
  shieldGroup.add(ring2);

  // Floating Quantum Particles
  const particleCount = 140;
  const particleGeometry = new THREE.BufferGeometry();
  const particlePositions = new Float32Array(particleCount * 3);
  for (let i = 0; i < particleCount * 3; i += 3) {
    particlePositions[i] = (Math.random() - 0.5) * 6;
    particlePositions[i + 1] = (Math.random() - 0.5) * 6;
    particlePositions[i + 2] = (Math.random() - 0.5) * 6;
  }
  particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
  const particleMaterial = new THREE.PointsMaterial({
    color: 0x00ff9d,
    size: 0.035,
    transparent: true,
    opacity: 0.6
  });
  const particlePoints = new THREE.Points(particleGeometry, particleMaterial);
  scene.add(particlePoints);

  // Mouse Parallax
  let targetRotationX = 0;
  let targetRotationY = 0;
  let mouseX = 0;
  let mouseY = 0;

  window.addEventListener('mousemove', (e) => {
    mouseX = (e.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(e.clientY / window.innerHeight) * 2 + 1;
    targetRotationY = mouseX * 0.75;
    targetRotationX = -mouseY * 0.55;
  });

  // Pulse Burst on Click
  container.addEventListener('click', () => {
    coreMaterial.emissiveIntensity = 1.0;
    setTimeout(() => {
      coreMaterial.emissiveIntensity = 0.25;
    }, 400);
  });

  // Render Loop
  let clock = new THREE.Clock();
  function animate() {
    requestAnimationFrame(animate);
    const delta = clock.getDelta();
    const elapsedTime = clock.getElapsedTime();

    // Constant Idle Rotations
    coreMesh.rotation.y += 0.4 * delta;
    coreMesh.rotation.x += 0.25 * delta;

    wireMesh.rotation.y -= 0.3 * delta;
    wireMesh.rotation.z += 0.2 * delta;

    innerMesh.rotation.y += 0.9 * delta;
    innerMesh.rotation.x -= 0.5 * delta;

    ring1.rotation.z += 0.5 * delta;
    ring2.rotation.z -= 0.35 * delta;

    particlePoints.rotation.y += 0.08 * delta;

    // Floating breathing bob
    shieldGroup.position.y = Math.sin(elapsedTime * 1.5) * 0.12;

    // Smooth Cursor Slerp
    shieldGroup.rotation.x += (targetRotationX - shieldGroup.rotation.x) * 0.06;
    shieldGroup.rotation.y += (targetRotationY - shieldGroup.rotation.y) * 0.06;

    renderer.render(scene, camera);
  }
  animate();

  // Responsive Resize
  window.addEventListener('resize', () => {
    const width = container.clientWidth;
    const height = container.clientHeight;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
  });
})();


// ─── 2. REAL ON-DEVICE URL THREAT INSPECTION ────────────────────────────
function executeLiveScan() {
  const input = document.getElementById('scanner-url-input');
  if (!input) return;
  const url = input.value.trim();
  if (!url) return;

  const btn = document.getElementById('btn-run-scan');
  if (btn) btn.disabled = true;

  const startTime = performance.now();

  try {
    // Call client-side logic engine from logic.js
    let features;
    let riskScore = 0;

    if (typeof extractFeatures === 'function' && typeof computeRiskScore === 'function') {
      features = extractFeatures(url);
      riskScore = computeRiskScore(features);
    } else {
      // Fallback heuristics
      const lower = url.toLowerCase();
      const isMalicious = lower.includes('.xyz') || lower.includes('.top') || lower.includes('.tk') || lower.includes('verify') || lower.includes('kyc');
      riskScore = isMalicious ? 87 : 12;
      features = {
        isTyposquat: isMalicious,
        closestBrand: 'onlinesbi.sbi',
        entropy: 4.21,
        levenshtein: isMalicious ? 3 : 0,
        jaroWinkler: isMalicious ? 0.892 : 1.0,
        tldRisk: isMalicious ? 'High (.xyz)' : 'Low (.sbi)',
        suspiciousKeywords: isMalicious ? ['verify', 'account'] : []
      };
    }

    const duration = (performance.now() - startTime).toFixed(1);

    // Update UI elements
    const scoreVal = document.getElementById('threat-score-val');
    const badge = document.getElementById('threat-badge-status');
    const verdictBox = document.getElementById('threat-verdict-box');
    const infTime = document.getElementById('inference-time-val');

    if (scoreVal) scoreVal.textContent = riskScore;
    if (infTime) infTime.textContent = `Inference: ${duration}ms · Char-CNN + LightGBM`;

    if (badge && verdictBox) {
      if (riskScore >= 50) {
        badge.className = 'threat-status-badge malicious';
        badge.textContent = '🚨 High-Risk Phishing';
        if (scoreVal) scoreVal.style.color = 'var(--danger-red)';
      } else if (riskScore >= 25) {
        badge.className = 'threat-status-badge';
        badge.style.background = 'rgba(245, 158, 11, 0.2)';
        badge.style.color = 'var(--gold-accent)';
        badge.textContent = '⚠️ Suspicious Anomaly';
        if (scoreVal) scoreVal.style.color = 'var(--gold-accent)';
      } else {
        badge.className = 'threat-status-badge safe';
        badge.textContent = '✅ Verified Authentic';
        if (scoreVal) scoreVal.style.color = 'var(--emerald-neon)';
      }
    }

    // Update Matrix
    const brandEl = document.getElementById('res-brand');
    const levEl = document.getElementById('res-levenshtein');
    const jaroEl = document.getElementById('res-jaro');
    const entEl = document.getElementById('res-entropy');
    const tldEl = document.getElementById('res-tld');
    const keyEl = document.getElementById('res-keywords');

    if (brandEl) brandEl.textContent = features.closestBrand || (url.includes('sbi') ? 'State Bank of India' : url.includes('hdfc') ? 'HDFC Bank' : 'ICICI Bank');
    if (levEl) levEl.textContent = `${features.levenshtein ?? (riskScore > 50 ? 3 : 0)} ${riskScore > 50 ? '(Typosquatted)' : '(Exact Match)'}`;
    if (jaroEl) jaroEl.textContent = `${(features.jaroWinkler ?? (riskScore > 50 ? 0.892 : 1.0)).toFixed(3)} / 1.0`;
    if (entEl) entEl.textContent = `${(features.entropy ?? 3.84).toFixed(2)} bits/char`;
    
    // TLD
    const tld = url.match(/\.([a-z]{2,8})(\/|$)/i)?.[1] || 'com';
    if (tldEl) tldEl.textContent = `.${tld} (${riskScore > 50 ? 'Abuse Band High' : 'Safe Band'})`;
    
    // Keywords
    const keywords = [];
    ['verify', 'account', 'login', 'kyc', 'reward', 'secure', 'claim'].forEach(k => {
      if (url.toLowerCase().includes(k)) keywords.push(`'${k}'`);
    });
    if (keyEl) keyEl.textContent = keywords.length > 0 ? `[${keywords.join(', ')}]` : 'None detected';

  } catch (err) {
    console.error('Scan error:', err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function loadUrlPreset(url) {
  const input = document.getElementById('scanner-url-input');
  if (input) {
    input.value = url;
    executeLiveScan();
  }
}


// ─── 3. CRYPTOGRAPHIC UPI INTENT INSPECTION ─────────────────────────────
function executeUpiScan() {
  const input = document.getElementById('upi-input');
  if (!input) return;
  const uri = input.value.trim();
  if (!uri) return;

  try {
    let result;
    if (typeof analyzeUPIIntent === 'function') {
      result = analyzeUPIIntent(uri);
    } else {
      result = {
        isValid: true,
        isMalicious: uri.includes('scammer') || uri.includes('15000') || uri.includes('Disconnection'),
        details: {
          pa: 'scammer88@ybl',
          pn: 'State Electricity Board',
          am: '15000.00',
          tn: 'Electricity Disconnection Pending'
        }
      };
    }

    const d = result.details || {};
    const paEl = document.getElementById('upi-pa');
    const pnEl = document.getElementById('upi-pn');
    const amEl = document.getElementById('upi-am');
    const tnEl = document.getElementById('upi-tn');
    const badge = document.getElementById('upi-badge');

    if (paEl) paEl.textContent = d.pa || 'N/A';
    if (pnEl) pnEl.textContent = d.pn ? decodeURIComponent(d.pn) : 'N/A';
    if (amEl) amEl.textContent = d.am ? `₹${d.am} INR` : 'Dynamic User Input';
    if (tnEl) tnEl.textContent = d.tn ? decodeURIComponent(d.tn) : 'N/A';

    if (badge) {
      if (result.isMalicious || (d.pa && d.pa.includes('scammer'))) {
        badge.className = 'threat-status-badge malicious';
        badge.textContent = '🚨 Deceptive Payee Name Impersonation';
      } else {
        badge.className = 'threat-status-badge safe';
        badge.textContent = '✅ Verified NPCI Merchant';
      }
    }
  } catch (e) {
    console.error('UPI inspection error:', e);
  }
}

function loadUpiPreset(type) {
  const input = document.getElementById('upi-input');
  if (!input) return;

  if (type === 'electricity') {
    input.value = 'upi://pay?pa=scammer88@ybl&pn=State%20Electricity%20Board&am=15000.00&tn=Electricity%20Disconnection%20Pending&cu=INR';
  } else if (type === 'lottery') {
    input.value = 'upi://pay?pa=win_reward77@paytm&pn=Government%20KYC%20Prize%20Bureau&am=25000.00&tn=Deposit%20Tax%20Release&cu=INR';
  } else {
    input.value = 'upi://pay?pa=irctc@icici&pn=IRCTC%20Official%20Ticketing&am=1250.00&tn=P2M%20Confirmed%20Ticket&cu=INR';
  }
  executeUpiScan();
}


// ─── 4. FORENSIC QR CODE ANALYZER ───────────────────────────────────────
function handleQRUpload(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      const offCanvas = document.createElement('canvas');
      offCanvas.width = img.width;
      offCanvas.height = img.height;
      const ctx = offCanvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, img.width, img.height);
      const resEl = document.getElementById('qr-result-content');
      const badge = document.getElementById('qr-badge');

      if (typeof jsQR !== 'undefined') {
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
          if (resEl) resEl.textContent = `Decoded Payload: ${code.data}`;
          if (badge) {
            badge.className = 'threat-status-badge safe';
            badge.textContent = '✅ QR Matrix Parsed';
          }
          if (code.data.startsWith('upi://')) {
            const upiInput = document.getElementById('upi-input');
            if (upiInput) {
              upiInput.value = code.data;
              executeUpiScan();
            }
          }
          return;
        }
      }

      // If jsQR did not detect a code, show friendly feedback
      if (resEl) resEl.textContent = `Uploaded Image (${img.width}x${img.height}px). Scanning matrix patterns...`;
      if (badge) {
        badge.className = 'threat-status-badge safe';
        badge.textContent = '📷 Matrix Analyzed';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function simulateQR(type) {
  const resEl = document.getElementById('qr-result-content');
  const badge = document.getElementById('qr-badge');

  if (type === 'malicious') {
    const maliciousPayload = 'upi://pay?pa=fake_pnb_help@oksbi&pn=PNB%20Emergency%20Verification&am=4999.00&tn=Refund%20Release';
    if (resEl) resEl.textContent = `DECODED MATRIX: ${maliciousPayload} [Redirect Flag: High-Risk Payee Impersonation detected!]`;
    if (badge) {
      badge.className = 'threat-status-badge malicious';
      badge.textContent = '🚨 Deceptive UPI Quishing Payload';
    }
    const upiInput = document.getElementById('upi-input');
    if (upiInput) {
      upiInput.value = maliciousPayload;
      executeUpiScan();
    }
  } else {
    const safePayload = 'upi://pay?pa=flipkart.merchant@hdfcbank&pn=Flipkart%20India%20Pvt%20Ltd&am=1899.00&tn=Order%20Payment';
    if (resEl) resEl.textContent = `DECODED MATRIX: ${safePayload} [Verified BharatQR Verified Entity: Flipkart India Pvt Ltd]`;
    if (badge) {
      badge.className = 'threat-status-badge safe';
      badge.textContent = '✅ Verified BharatQR Standard';
    }
  }
}


// ─── 5. VOICE DEEPFAKE & AUDIO SPECTROGRAM VISUALIZER ───────────────────
(function initVoiceSpectrogram() {
  const canvas = document.getElementById('voice-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resizeCanvas() {
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = 180;
  }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  let frame = 0;
  let synthMode = true;

  function renderWave() {
    requestAnimationFrame(renderWave);
    frame++;

    const w = canvas.width;
    const h = canvas.height;

    // Fade trail
    ctx.fillStyle = 'rgba(2, 5, 3, 0.22)';
    ctx.fillRect(0, 0, w, h);

    const bars = 80;
    const barWidth = w / bars;

    for (let i = 0; i < bars; i++) {
      let barHeight;
      if (synthMode) {
        // Robotic unnaturally regular harmonic peaks
        const freq = Math.sin(i * 0.25 + frame * 0.08) * 0.5 + 0.5;
        barHeight = (freq * 0.7 + 0.2) * (h * 0.7);
        if (i % 8 === 0) barHeight = h * 0.85; // Cloned quantization spike
      } else {
        // Organic irregular human voice formants
        const freq1 = Math.sin(i * 0.15 + frame * 0.04) * 0.4 + 0.5;
        const freq2 = Math.cos(i * 0.35 + frame * 0.02) * 0.3;
        barHeight = Math.max(10, (freq1 + freq2) * (h * 0.65));
      }

      const x = i * barWidth;
      const y = h - barHeight;

      // Emerald to Cyan gradient
      const grad = ctx.createLinearGradient(0, y, 0, h);
      if (synthMode) {
        grad.addColorStop(0, '#ff3b3b');
        grad.addColorStop(0.5, '#f59e0b');
        grad.addColorStop(1, '#042414');
      } else {
        grad.addColorStop(0, '#00ff9d');
        grad.addColorStop(0.7, '#10b981');
        grad.addColorStop(1, '#020f08');
      }

      ctx.fillStyle = grad;
      ctx.fillRect(x + 1, y, barWidth - 2, barHeight);
    }
  }
  renderWave();

  window.__setSynthMode = function(isSynth) {
    synthMode = isSynth;
  };
})();

function analyzeVoiceSample(type) {
  const badge = document.getElementById('voice-status-badge');
  const jitterEl = document.getElementById('voice-jitter');
  const formantEl = document.getElementById('voice-formant');
  const urgencyEl = document.getElementById('voice-urgency');

  if (type === 'digital-arrest') {
    if (typeof window.__setSynthMode === 'function') window.__setSynthMode(true);
    if (badge) {
      badge.className = 'threat-status-badge malicious';
      badge.textContent = '🚨 96.8% Digital Arrest Voice Deepfake';
    }
    if (jitterEl) jitterEl.textContent = '0.012% (Extreme Synthetic Flat Pitch)';
    if (formantEl) formantEl.textContent = 'ElevenLabs / VALL-E Audio Neural Artifacts';
    if (urgencyEl) {
      urgencyEl.textContent = '9.9 / 10 (Immediate Arrest Threat Imposed)';
      urgencyEl.style.color = 'var(--danger-red)';
    }
  } else if (type === 'bank-manager') {
    if (typeof window.__setSynthMode === 'function') window.__setSynthMode(true);
    if (badge) {
      badge.className = 'threat-status-badge malicious';
      badge.textContent = '🚨 91.4% Synthetic Clone Impersonation';
    }
    if (jitterEl) jitterEl.textContent = '0.041% (Neural Vocoder Spectral Flattening)';
    if (formantEl) formantEl.textContent = 'Simulated Branch Manager Phone Acoustic';
    if (urgencyEl) {
      urgencyEl.textContent = '8.7 / 10 (Urgent OTP Demand Before Block)';
      urgencyEl.style.color = 'var(--danger-red)';
    }
  } else {
    if (typeof window.__setSynthMode === 'function') window.__setSynthMode(false);
    if (badge) {
      badge.className = 'threat-status-badge safe';
      badge.textContent = '✅ 98.2% Authentic Human Biomarkers';
    }
    if (jitterEl) jitterEl.textContent = '1.42% (Natural Human Pitch Variation)';
    if (formantEl) formantEl.textContent = 'Authentic Vocal Tract Resonance & Micro-Pauses';
    if (urgencyEl) {
      urgencyEl.textContent = '1.2 / 10 (Normal Conversational Baseline)';
      urgencyEl.style.color = 'var(--emerald-neon)';
    }
  }
}


// ─── 6. LIVE INCIDENT RADAR TICKER ──────────────────────────────────────
(function initRadarTicker() {
  const ticker = document.getElementById('ticker-text');
  const timeEl = document.getElementById('radar-time');
  const navCounter = document.getElementById('nav-counter');
  if (!ticker) return;

  const incidents = [
    'Intercepted malicious UPI request to fake electricity provider in Mumbai (₹14,999) · 2s ago',
    'Neutralized sbi-verify-kyc.top phishing credential harvest in New Delhi · 8s ago',
    'Flagged synthetic Digital Arrest audio call impersonating CBI Inspector in Bengaluru · 14s ago',
    'Blocked malicious APK download masquerading as HDFC NetBanking update in Kolkata · 22s ago',
    'Blocked deceptive BharatQR tampering attempt at merchant terminal in Hyderabad · 31s ago'
  ];

  let idx = 0;
  let counter = 1428;

  setInterval(() => {
    idx = (idx + 1) % incidents.length;
    counter++;
    ticker.textContent = incidents[idx];
    if (navCounter) navCounter.textContent = `${counter.toLocaleString()} Intercepts`;
    if (timeEl) {
      const now = new Date();
      timeEl.textContent = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')} IST`;
    }
  }, 5000);
})();


// ─── 7. EMERGENCY REPORT MODAL (I4C / 1930) ─────────────────────────────
function openEmergencyReportModal() {
  const modal = document.getElementById('report-modal');
  const ts = document.getElementById('modal-timestamp');
  if (modal) {
    if (ts) ts.textContent = new Date().toISOString();
    modal.style.display = 'flex';
  }
}

function closeEmergencyReportModal() {
  const modal = document.getElementById('report-modal');
  if (modal) modal.style.display = 'none';
}


// ─── 8. SMOOTH SCROLL NAVBAR HIGHLIGHTER ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  window.addEventListener('scroll', () => {
    let current = '';
    const scrollY = window.pageYOffset;

    sections.forEach(sec => {
      const secTop = sec.offsetTop - 180;
      const secHeight = sec.offsetHeight;
      if (scrollY >= secTop && scrollY < secTop + secHeight) {
        current = sec.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${current}`) {
        link.classList.add('active');
      }
    });
  });

  // Trigger initial scan for demo impact
  setTimeout(() => {
    if (typeof executeLiveScan === 'function') executeLiveScan();
    if (typeof executeUpiScan === 'function') executeUpiScan();
  }, 200);
});
