# Getting Started Guide - RakshaLink AI

This guide walks you through running, testing, and exploring the **RakshaLink AI On-Device Anti-Phishing & Fraud Prevention Platform** on your local machine.

---

## 🚀 Quick Start (Running the Local Server)

The application is built using lightweight, high-performance HTML5, CSS3, and JavaScript, served via a standard HTTP server.

### 1. Open Terminal / PowerShell in the Project Directory
Navigate to the project root directory:
```powershell
cd "c:\Users\raksh\OneDrive\Desktop\New folder (2)"
```

### 2. Launch the HTTP Web Server
Run Python's built-in HTTP server on port `8080`:
```powershell
python -m http.server 8080
```
*(Alternatively, if port 8080 is occupied, run `python -m http.server 3000`)*

### 3. Open in Browser
Open your preferred web browser and navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

---

## 🧪 Interactive Testing & Features Walkthrough

Once the app opens in your browser, you can explore and test all **7 screen interfaces**:

### 1. 📊 Home Dashboard (Screen 6)
- View macro-financial threat metrics (MHA & I4C data).
- Use the **Real-Time URL Threat Inspector**:
  - Type or paste any link (e.g. `http://sbi-secure-login.xyz/verify-account`).
  - Click **Execute On-Device ML Inference**.
  - Test preset buttons like `sbi-secure-login.xyz` (Malicious) or `https://onlinesbi.sbi` (Safe).

### 2. 🧠 Detailed Analysis / ML Engine (Screen 1)
- Inspect the sub-100ms **Character-Level CNN** parameters (128-dim embeddings, 70-symbol vocabulary).
- Review the **36-feature LightGBM decomposition matrix** (Lexical, Structural, Domain Entropy, Semantic keywords).

### 3. 🔍 Malicious Scan Result (Screen 3)
- Examine an example threat detection breakdown featuring **Levenshtein Distance** and **Jaro-Winkler prefix matching** for typosquatting domains.

### 4. ⚡ UPI Intent Security Interceptor (Screen 2)
- Test UPI URI schemes like:
  `upi://pay?pa=scammer88@ybl&pn=State%20Electricity%20Board&am=15000.00&cu=INR`
- Click **Cryptographically Inspect UPI Intent Payload**.
- Observe how the engine detects **Payee Name Deception** and enforces explicit target package binding (`Intent.setPackage()`).

### 5. 💬 SMS Interceptor (Screen 7)
- View simulated incoming SMS notifications processed by Android's `BIND_NOTIFICATION_LISTENER_SERVICE`.
- See how electricity disconnection and task scams are flagged in real-time.

### 6. 🚨 Phishing Warning Screen (Screen 5)
- Preview the emergency full-screen red warning block page displayed when high-risk URLs or tampered UPI links are intercepted.

### 7. 🛡️ Brand Assets (Screen 4)
- View the 3D metallic cyber shield logo and design system specifications.

---

## 📁 Project Structure

```
New folder (2)/
├── index.html                  # Main application structure & all 7 screen layouts
├── styles.css                  # Modern cyber dark design system & UI animations
├── app.js                      # On-device ML simulation, edit distance, & UPI parsing
├── rakshalink_shield_logo.jpg  # 3D Shield Logo asset
├── rakshalink_threat_banner.jpg# Mobile Threat Banner asset
└── GETTING_STARTED.md          # Setup and usage guide
```

---

## 🔧 Troubleshooting

- **Server Not Responding**: Ensure `python -m http.server 8080` is running in your terminal.
- **Port Conflict**: If port 8080 is already in use, run `python -m http.server 8081` and access `http://localhost:8081`.
- **Browser Compatibility**: Recommended on Chrome, Edge, Firefox, or Safari with JavaScript enabled.
