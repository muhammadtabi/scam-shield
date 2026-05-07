# ML Training Guide — Scam Shield
## Run this on Google Colab (Free GPU/CPU)

### Datasets to Download (All Free)

| Model | Dataset | Source |
|-------|---------|--------|
| Email/SMS Scam | SMS Spam Collection | https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset |
| Email/SMS Scam | Enron Spam Dataset | https://www.kaggle.com/datasets/wanderfj/enron-spam |
| URL Detection | Phishing Site URLs | https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls |
| URL Detection | PhishTank Database | https://phishtank.org/developer_info.php |

### Notebook Files (in /notebooks folder)
1. `01_email_sms_model.ipynb` — Email & SMS scam detection model
2. `02_url_model.ipynb` — URL/phishing detection model  
3. `03_model_evaluation.ipynb` — Precision, Recall, F1 evaluation

### After Training — Export Models
```python
import joblib

# Save trained model
joblib.dump(email_model, 'saved_models/email_scam_model.pkl')
joblib.dump(vectorizer,  'saved_models/tfidf_vectorizer.pkl')
joblib.dump(url_model,   'saved_models/url_scam_model.pkl')
```

Then download the `.pkl` files and place them in:
`backend/app/ml/models/`
