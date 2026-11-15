# ROADMAP.md — Scam Shield Implementation Roadmap

## Completed Phases
- [x] Phase 1: Project structure, scikit-learn models & feature extractors
- [x] Phase 2: FastAPI backend, JWT authentication, and MongoDB in-memory fallback
- [x] Phase 3: Minimalist React frontend with 7-day threat activity chart
- [x] Phase 4: Full-stack /unslop audit, copy deslop, and slate design system overhaul
- [x] Phase 5: Manifest V3 browser extension for real-time URL threat defense
- [x] Phase 6: Real-time SMS inbox monitoring and smishing defense

---

## Phase 7: Security Training & Phishing Awareness Simulation
- [x] 7.1 Backend Training Schema & Service:
  - Create `backend/app/schemas/training.py`
  - Create `backend/app/services/training_service.py` with 8 curated scenarios and scoring logic
- [x] 7.2 Backend Training API Routes & Tests:
  - Create `backend/app/api/routes/training.py`
  - Mount router in `backend/main.py`
  - Add test suite in `backend/tests/test_training.py`
- [x] 7.3 Frontend Training Interface:
  - Add training API methods in `frontend/src/api/client.js`
  - Create `frontend/src/components/training/Training.jsx`
  - Add navigation item in `frontend/src/components/shared/Sidebar.jsx` and `frontend/src/App.jsx`
- [x] 7.4 Verification & Commit:
  - Run full pytest suite (all tests passing)
  - Run `npm run build` (clean compilation)
  - Verify unslop compliance
  - Atomic conventional git commit
