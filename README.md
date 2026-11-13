# 🛡️ Scam Shield — Scam Detection Dashboard

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

## 📬 Gmail Inbox Monitoring

This project can watch one Gmail inbox, classify each new message as safe, suspicious, or scam, and log it into the existing alerts/history view.

### 1) Create Google OAuth credentials
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project.
3. Enable the Gmail API.
4. Configure the OAuth consent screen.
5. Create an OAuth client ID of type Web application.
6. Add this redirect URI exactly:
    `http://localhost:8000/api/gmail/callback`

### 2) Add backend environment variables
Set these in `backend/.env`:

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/gmail/callback
FRONTEND_URL=http://localhost:5173
GMAIL_POLL_INTERVAL_SECONDS=60
```

### 3) Start the app locally
1. Start MongoDB and the backend.
2. Start the frontend.
3. Open the dashboard and click `Connect Gmail`.
4. Sign in to the Gmail account you want to monitor.
5. Grant read-only Gmail access.

### 4) Verify it works
1. Send a fresh email to that Gmail inbox.
2. Wait for the poll interval or click `Sync now` on the dashboard.
3. Check the Alerts page for a new Gmail entry.

### Notes
- The first release uses polling, not Gmail push notifications.
- The monitored account is read-only; the app does not send, delete, or archive mail.
- If you deploy to Render or another host, the Gmail redirect URI must match the deployed backend URL, not localhost.

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
- ✅ Feature-Level Explanations
- ✅ Real-time Alerts Dashboard
- ✅ PDF/CSV Report Export
- ✅ Evidence Logging
