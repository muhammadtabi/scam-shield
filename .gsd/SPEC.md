# SPEC.md — Scam Shield Browser Extension Specification

> **Status**: `FINALIZED`
>
> **Project Profile**: Web Extension (Manifest V3) + FastAPI Integration

---

## 1. Vision & Purpose
Scam Shield Browser Extension provides instant, real-time threat protection directly inside the browser. It monitors active web pages, scans links for phishing/malware patterns against the Scam Shield API, displays visual threat level badges on the toolbar, and alerts users before they interact with malicious domains.

---

## 2. Goals
1. **Real-Time Active Tab Protection**: Inspect current page URLs automatically as the user browses and update the extension icon badge (Green = Safe, Amber = Suspicious, Red = Scam).
2. **Interactive Popup Dashboard**: Sleek Manifest V3 popup adhering to the Scam Shield minimalist slate design system, showing confidence score, detection factors, and technical explanations.
3. **Ad-Hoc URL Quick Scanner**: Allow users to paste and analyze any suspicious URL without navigating to it.
4. **Seamless Backend Sync**: Works anonymously out-of-the-box, or connects to the user's Scam Shield account via JWT to log detections to the dashboard history.
5. **Malicious Interstitial Warning**: Displays a non-intrusive warning banner when navigating to high-risk scam sites.

---

## 3. Non-Goals (Out of Scope)
- Full DOM keylogging or password form inspection (preserves user privacy).
- Network packet sniffing or VPN tunneling.
- Modifying page content other than safety warning banners.

---

## 4. Technical Architecture
```
extension/
├── manifest.json              # Chrome / Firefox Manifest V3
├── icons/                     # 16px, 32px, 48px, 128px toolbar & badge icons
├── background/
│   └── background.js          # Service worker: tab updates, badge colors, API caching
├── popup/
│   ├── popup.html             # Minimalist slate popup interface
│   ├── popup.css              # Styling matching Scam Shield design tokens
│   └── popup.js               # Tab query, URL scan client, account sync
├── content/
│   ├── content.js             # High-risk interstitial warning banner
│   └── content.css            # Clean warning banner styles
└── README.md                  # Extension installation & developer guide
```

---

## 5. API Requirements
- `POST /api/detect/url`: Support optional authentication via `get_optional_current_user`.
  - Unauthenticated requests: evaluate URL, return verdict and reasons without database write.
  - Authenticated requests: evaluate URL, persist result to `db.detections`, return verdict with ID.
- `GET /health`: Endpoint for extension to check backend reachability.

---

## 6. Success Criteria
- [x] Manifest V3 compliant (compatible with Google Chrome, Chromium, Brave, Edge).
- [x] Backend endpoint `POST /api/detect/url` accepts both authenticated and unauthenticated scans.
- [x] Extension popup provides real-time scan, ad-hoc scan, and server status.
- [x] Automated backend tests verify optional auth and URL scanning.
- [x] Zero external dependencies required to load the extension in developer mode (`chrome://extensions`).

