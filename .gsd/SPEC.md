# SPEC.md — Scam Shield Project Specification

> **Status**: `FINALIZED`
>
> **Project Profile**: Full-Stack Threat Defense & Security Training Platform

---

## 1. Vision & Purpose
Scam Shield is an end-to-end scam detection and cybersecurity awareness platform. It combines calibrated machine learning (Logistic Regression, TF-IDF, ExtraTrees, lexical heuristics) with actionable awareness tools: real-time email inspection, SMS smishing monitoring, active browser URL defense, and an interactive **Security Training & Phishing Awareness Simulation** that empowers users to recognize sophisticated social engineering attacks.

---

## 2. Key Capabilities
1. **Multi-Channel Threat Detection**: Unified analysis for Email headers/bodies, SMS messages with carrier shortcode recognition, and scheme-invariant URL inspection.
2. **Browser Extension (Manifest V3)**: Real-time toolbar badges and in-page warnings for high-risk scam URLs.
3. **SMS Smishing Inbox**: Real-time webhook ingestion, Android backup import, and smishing simulation presets.
4. **Gmail Inbox Integration**: Read-only IMAP/OAuth monitor with automated threat explanations.
5. **Security Training & Phishing Awareness**: Interactive training sandbox with curated real-world scenarios across Email, SMS, and URLs, comparing human judgment against calibrated ML verdicts with educational feedback and accuracy tracking.

---

## 3. Training Module Specification
- **Curated Scenarios**: High-fidelity representations of modern attack vectors (e.g. Bank OTP vs fake shortcode, USPS delivery lures, display-name spoofing, cloud credential harvesting, advance-fee prize fraud) alongside legitimate benign baselines.
- **Interactive Evaluation**: Users classify each scenario as `safe` or `scam` and highlight observed indicators.
- **Feedback & Ground Truth**: Instant comparative breakdown highlighting human selection vs ML confidence score and factor explanations.
- **User Progress**: Tracks completed scenarios, accuracy percentage, and security tier rank per user account.

---

## 4. Technical Architecture
```
backend/
├── app/
│   ├── api/routes/training.py      # Training scenarios, submissions, and stats endpoints
│   ├── schemas/training.py         # Pydantic models for training scenarios and results
│   └── services/training_service.py# Scenario repository and scoring logic
frontend/
└── src/
    └── components/
        └── training/
            └── Training.jsx        # Interactive training & awareness simulator UI
```

---

## 5. Success Criteria
- [x] All training endpoints tested with unit tests (`backend/tests/test_training.py`).
- [x] Frontend compiles with zero warnings or errors.
- [x] Full adherence to Scam Shield minimal zinc/slate design tokens and /unslop copy guidelines.
