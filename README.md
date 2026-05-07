# 🛡️ Scam Shield — AI-Powered Scam Detection Dashboard

**Final Year Project | COMSATS University Islamabad, Attock Campus**
**Students:** Muhammad Tayyaab | Aqib Rahim
**Supervisor:** Dr. Khalid Mehmood Awan

---

## 🚀 Tech Stack

| Layer | Technology | Hosting |
|-------|-----------|---------|
| Frontend | React.js + Vite + Tailwind | Vercel (Free) |
| Backend | Python FastAPI | Render (Free) |
| Database | MongoDB Atlas | Atlas Free Tier |
| ML Training | Scikit-learn | Google Colab |
| Auth | JWT Tokens | — |
| XAI | LIME | — |

---

## 📁 Project Structure

```
scam-shield/
├── backend/          # FastAPI server + ML models
│   ├── app/
│   │   ├── api/routes/    # auth, detection, reports, dashboard
│   │   ├── core/          # config, security
│   │   ├── db/            # MongoDB connection
│   │   ├── ml/            # ML model loading & prediction
│   │   ├── models/        # MongoDB document models
│   │   ├── schemas/       # Pydantic request/response schemas
│   │   └── services/      # Business logic
│   ├── main.py
│   └── requirements.txt
│
├── frontend/         # React + Vite dashboard
│   └── src/
│       ├── components/    # dashboard, auth, alerts, reports
│       ├── pages/
│       ├── hooks/
│       └── utils/
│
└── ml-training/      # Google Colab notebooks
    ├── notebooks/
    ├── datasets/
    └── saved_models/
```

---

## 🔧 Local Setup

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # Fill in your values
uvicorn main:app --reload
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

---

## 📋 Build Phases

- [x] Phase 1 — Project Structure
- [ ] Phase 2 — ML Model Training (Google Colab)
- [ ] Phase 3 — FastAPI Backend
- [ ] Phase 4 — React Frontend Dashboard
- [ ] Phase 5 — LIME Explainability
- [ ] Phase 6 — Deployment

---

## 🌐 Features
- ✅ Email/Text Scam Detection
- ✅ URL/Website Analysis
- ✅ Phone Number Spam Check
- ✅ Explainable AI (LIME)
- ✅ Real-time Alerts Dashboard
- ✅ PDF/CSV Report Export
- ✅ Evidence Logging
