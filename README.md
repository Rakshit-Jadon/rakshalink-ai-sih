# RakshaLink AI

RakshaLink AI is an on-device cybersecurity prototype focused on protecting users from phishing, fake banking pages, UPI fraud, and malicious URL-based scams. The project combines a browser extension, a threat-scoring engine, and a web-based dashboard to detect suspicious links before they can fool users into sharing OTPs, passwords, or sensitive payment details.

This repository contains both:
- a demo web application dashboard showcasing threat intelligence and ML-style detection logic
- a browser extension called `mule-phish-guard` that evaluates URLs and blocks dangerous pages in real time

---

## Project Overview

The project is designed around the growing problem of Indian digital fraud, especially:
- phishing websites impersonating banks and UPI services
- fake links sent through SMS, WhatsApp, or email
- lookalike domains using typosquatting or suspicious TLDs
- malicious UPI deep links and credential-harvesting flows

RakshaLink AI aims to detect these patterns locally on the device using heuristics and URL analysis without sending user data to a remote server.

---

## What This Project Does

### 1. Phishing URL Detection
The system flags URLs that exhibit risky signals such as:
- fake or lookalike bank domains
- suspicious TLDs like `.xyz`, `.tk`, `.cf`, `.gq`, etc.
- forced urgency keywords like `verify`, `kyc`, `block`, `refund`, `urgent`
- encoded/hidden redirect patterns
- use of `@` symbols, IP addresses, or URL shorteners
- typosquatting near real financial services

### 2. UPI Fraud Prevention
The project includes logic for evaluating UPI payment deep links and catching patterns such as:
- random-looking VPA names
- suspicious payee names or fake merchant impersonation
- unsafe or deceptive UPI payload structures

### 3. Web Dashboard / Demo UI
The main interface in `index.html` presents a dashboard, threat feed, model metrics, detection console, and security analysis pages. It simulates a live security panel that demonstrates risk scoring and prevention workflows.

### 4. Browser Extension Protection
The extension under `mule-phish-guard/` monitors navigation and blocks dangerous URLs before the user lands on a malicious page. It also shows a warning interstitial if the risk is high.

---

## Tech Stack

### Frontend / Demo
- HTML5
- CSS3
- JavaScript (Vanilla JS)
- Static web serving via Python HTTP server

### Browser Extension
- Chrome Manifest V3
- Background service worker
- Content scripts
- Popup UI
- Local storage and session storage

### Detection Logic
- URL parsing and normalization
- Levenshtein distance and similarity matching
- brand impersonation checks
- suspicious keyword scanning
- TLD and protocol risk heuristics
- local risk scoring engine

---

## Architecture

The project has two main parts:

### A. Standalone Security Dashboard
This is the main user-facing demonstration page in the repository root:
- `index.html` contains the UI screens
- `styles.css` provides the cyber-style visual design
- `app.js` contains the detection logic and UI interaction code

This dashboard simulates:
- live threat monitoring
- risk scoring for URLs
- phishing and fraud analysis
- model confidence display
- system flow explanations

### B. Chrome Extension
The extension folder `mule-phish-guard/` contains:
- `manifest.json` — extension configuration
- `background.js` — navigation interception and blocking logic
- `heuristics.js` — risk evaluation engine
- `content.js` — in-page checks and overlays
- `popup.html` / `popup.js` — extension popup UI
- `warning.html` / `warning.js` — block page shown when a dangerous site is detected

This allows the project to evaluate links in real time while the browser loads a page.

---

## Key Features

- Real-time URL risk evaluation
- Brand impersonation detection for major Indian banks and UPI providers
- Suspicious keyword analysis
- Deep-link protection for UPI flows
- Visual dashboard with metrics and threat panels
- Browser-level blocking using extension logic
- Privacy-first design: no remote transmission required for local heuristic checks
- Demo assets for threat simulation and UI showcase

---

## Project Structure

```text
rakshalink-ai-sih/
├── app.js                     # Main dashboard logic and risk scoring
├── index.html                 # Demo dashboard UI and screen layouts
├── styles.css                 # Global styling and dashboard theme
├── README.md                  # Project documentation
├── GETTING_STARTED.md         # Quick setup guide
├── vercel.json                # Deployment config for Vercel hosting
├── .env.example               # Example environment configuration
├── rakshalink_shield_logo.jpg # Brand asset
├── rakshalink_threat_banner.jpg # Threat banner asset
├── downloads/                 # APK / zip demo downloads
│   └── ...
├── mule-phish-guard/          # Chrome extension source
│   ├── background.js
│   ├── content.js
│   ├── heuristics.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── warning.html
│   ├── warning.js
│   ├── overlay.css
│   ├── popup.css
│   └── icons/
└── package-lock.json
```

---

## Running the Project Locally

### Option 1: Run the Dashboard Demo
From the project root, start a local web server:

```bash
python -m http.server 8080
```

Then open in the browser:

```text
http://localhost:8080
```

### Option 2: Run the Browser Extension
1. Open Chrome and go to:
   ```text
   chrome://extensions/
   ```
2. Enable Developer Mode.
3. Click Load unpacked.
4. Select the folder:
   ```text
   mule-phish-guard/
   ```
5. Visit a suspicious page or test a risky URL to see detection behavior.

---

## Demo Usage

### Testing the dashboard
The dashboard includes demo flows for:
- URL scanner
- UPI security analyzer
- SMS interception simulation
- QR analysis panels
- threat detection console
- model performance metrics

You can test with risky sample URLs like:

```text
http://sbi-secure-login.xyz/verify-account
https://example.com
upi://pay?pa=scammer88@ybl&pn=State%20Electricity%20Board&am=15000.00&cu=INR
```

### Extension behavior
When the extension identifies a dangerous URL, it can:
- mark the tab with a badge
- store the scan result in browser storage
- redirect to a warning page, depending on risk level

---

## How the Detection Works

The detection engine combines multiple heuristics to assign a risk score. It checks for:

- domain closeness to protected brands
- suspicious TLDs
- brand keyword stuffing
- link shorteners
- urgency language
- HTTPS absence
- IP-based hosts
- presence of `@` in URLs
- UPI-specific malicious patterns

The scoring logic then classifies the result as low, medium, or high risk. In the demo dashboard, these values are displayed as part of the security analysis.

---

## Privacy and Security Model

This project is intentionally privacy-focused:
- detection happens on-device
- no sensitive data is sent to a remote AI service in the prototype flow
- all browser checks are local and lightweight

This makes it suitable as a concept demonstrator for privacy-preserving fraud defense.

---

## Limitations

This is a prototype and not a production-grade security system. Some limitations include:
- heuristics-based detection rather than full production threat intelligence
- limited brand database and static rules
- no real external ML model deployment or secure inference pipeline
- no production-grade certificate, browser policy, or enterprise telemetry stack

---

## Future Enhancements

Potential improvements for a production version include:
- integrate a real machine learning model with TensorFlow Lite or browser-based inference
- fetch signed threat feeds from a trusted backend
- expand the protected brand list and finance-specific patterns
- add Android app integration for SMS and transaction monitoring
- support enterprise logging and audit trails
- add stronger protections for QR, app deep links, and digital payment flows

---

## License

This project is currently distributed for educational and prototype use. Please check the repository license file if one is added later.

---

## Contributing

Contributions are welcome for improving:
- detection logic
- UI/UX improvements
- browser extension stability
- new scam pattern coverage
- deployment packaging and documentation

If you are extending the project, keep the user privacy and local-processing model in mind.

---

## Summary

RakshaLink AI is a concept project that demonstrates how phishing and payment fraud prevention can be handled locally in a browser and dashboard environment. It combines a user-friendly educational interface with practical anti-phishing detection logic aimed at helping users recognize malicious links before they can be abused.

---

## Quick Start Summary

```bash
cd "<project-folder>"
python -m http.server 8080
```

Then visit:

```text
http://localhost:8080
```

For the extension:

```text
chrome://extensions/ -> Developer Mode -> Load unpacked -> mule-phish-guard/
```
