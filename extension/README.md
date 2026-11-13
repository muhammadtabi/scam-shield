# 🛡️ Scam Shield Browser Extension

Real-time scam detection and phishing protection browser extension (Manifest V3) powered by the Scam Shield FastAPI ML engine.

---

## 🚀 Features

* **Active Tab Protection:** Automatically inspects visited URLs and updates the toolbar badge (`SAFE` in green, `WARN` in amber, `SCAM` in red).
* **Popup Dashboard:** Minimalist dark slate UI displaying:
  * Current page domain and threat verdict
  * Confidence score meter
  * Detection factors and explanations
  * One-click re-scan
* **Quick Scanner:** Analyze any ad-hoc URL directly without navigating to it.
* **In-Page Interstitial Warning:** Renders a prominent safety banner on confirmed high-confidence malicious websites.
* **Account Sync (Optional):** Attach your Scam Shield JWT bearer token to sync all extension scans with your dashboard history and PDF incident reports.

---

## 📦 How to Install (Developer Mode)

### Google Chrome / Brave / Edge / Chromium

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions` / `brave://extensions`).
2. Enable **Developer mode** using the toggle in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the `extension/` folder in this repository:
   ```
   /home/chernobyl/Data/scam-shield/extension
   ```
5. The **Scam Shield** icon will appear in your browser toolbar. Pin it for quick access!

---

## ⚙️ Configuration & Testing

1. Ensure the Scam Shield backend server is running:
   ```bash
   ./scripts/start-project.sh
   # Or manually:
   PYTHONPATH=backend backend/venv/bin/uvicorn main:app --port 8000
   ```
2. Click the Scam Shield extension icon:
   * The **API** status indicator will show a green dot when connected to `http://localhost:8000`.
   * Under the **Settings** tab, you can customize the backend URL or paste your user JWT token.
3. **Try Scanning:**
   * Safe URL: `https://github.com` or `https://login.salesforce.com/` (Badge: `SAFE`)
   * Malicious/Phishing test URL: `http://paypal-secure-verify.xyz/login/confirm` (Badge: `SCAM` + Warning Banner)

