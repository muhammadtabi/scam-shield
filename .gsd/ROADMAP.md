# ROADMAP.md — Scam Shield Extension Roadmap

## Phases

### Phase 1: Backend API Enhancement
- [ ] Implement `get_optional_current_user` in `backend/app/core/dependencies.py`
- [ ] Update `detect_url_route` in `backend/app/api/routes/detection.py` to allow optional authentication
- [ ] Add unit & integration tests for authenticated vs anonymous URL detection in `backend/tests/test_url_detection.py`

### Phase 2: Extension Manifest & Service Worker
- [ ] Create `extension/manifest.json` with Manifest V3 permissions (`activeTab`, `storage`, `alarms`)
- [ ] Create SVG/PNG extension icons in `extension/icons/`
- [ ] Implement `extension/background/background.js` for tab navigation listeners, API caching, and badge status updates

### Phase 3: Popup Interface & Quick Scanner
- [ ] Build `extension/popup/popup.html` with minimalist zinc/slate layout
- [ ] Build `extension/popup/popup.css` matching Scam Shield design system tokens
- [ ] Implement `extension/popup/popup.js` for current tab scanning, manual URL check, and API health status

### Phase 4: Interstitial Safety Warning
- [ ] Implement `extension/content/content.js` to render warning banner on high-confidence scam domains
- [ ] Style `extension/content/content.css` with dismissible warning modal

### Phase 5: Verification & Documentation
- [ ] Run backend pytest test suite to verify 0 regressions
- [ ] Create `extension/README.md` with step-by-step developer loading instructions
- [ ] Atomic git commit

