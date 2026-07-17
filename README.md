<<<<<<< HEAD
# Phishing URL Detection Website

A Flask web application that uses a machine learning classifier to detect phishing URLs in real time. Enter any URL and get an instant risk score, verdict, and a breakdown of the specific signals that drove the prediction — all without fetching the destination page, so it's safe to check untrusted links.

## Features

- **Real-time URL analysis** — results in well under a second, no page content is ever fetched
- **ML classification** — a Random Forest model trained on ~80K labeled URLs (phishing vs. legitimate)
- **26 engineered features** per URL: length stats, special-character counts, domain entropy, suspicious keywords, IP-literal hosts, URL shorteners, suspicious TLDs, and more
- **Explainable results** — the UI surfaces the top contributing signals for every prediction, not just a bare score
- **Simple JSON API** (`POST /predict`) for integrating the detector into other tools

## How it works

1. **Feature extraction** (`features.py`) parses the raw URL string and computes lexical/structural features — no DNS lookups, no WHOIS, no network calls.
2. **Model training** (`model/train_model.py`) downloads a public labeled URL dataset, extracts features for a balanced sample, and trains a `RandomForestClassifier`.
3. **Serving** (`app.py`) loads the trained model once at startup and exposes a small Flask app + JSON API for predictions.

## Project structure

```
phishing-detector/
├── app.py                  # Flask application
├── features.py              # URL feature extraction (shared by training & serving)
├── requirements.txt
├── model/
│   ├── train_model.py       # Downloads dataset, trains & evaluates the model
│   ├── phishing_model.pkl   # Trained model (committed, ~4 MB)
│   └── metrics.json         # Evaluation metrics from the last training run
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

## Setup

```bash
git clone <your-repo-url>
cd phishing-detector
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

The repository already includes a trained model (`model/phishing_model.pkl`), so you can run the app immediately. To retrain from scratch (e.g. after changing features):

```bash
python model/train_model.py
```

This downloads the training dataset automatically on first run (no manual download needed) and overwrites `model/phishing_model.pkl` + `model/metrics.json`.

## Running the app

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

## API

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "paypal-secure-login.verify-account.tk/webscr?cmd=login"}'
```

Response:

```json
{
  "url": "paypal-secure-login.verify-account.tk/webscr?cmd=login",
  "prediction": "phishing",
  "phishing_probability": 77.16,
  "legit_probability": 22.84,
  "top_signals": [
    { "name": "num_hyphens", "explanation": "Number of hyphens in the URL", "importance": 0.08, "value": 3 },
    ...
  ]
}
```

## Model performance

Trained on a balanced sample of 80,000 URLs (40K phishing / 40K legitimate), held-out test accuracy:

| Metric    | Score |
|-----------|-------|
| Accuracy  | ~0.88 |
| Precision | ~0.90 |
| Recall    | ~0.87 |
| F1        | ~0.88 |

Full metrics from the last training run are in `model/metrics.json`.

## Dataset & credits

Training data: a public labeled URL dataset (`good`/`bad`) from [faizann24/Using-machine-learning-to-detect-malicious-URLs](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs). The raw dataset is not committed to this repo (it's ~22 MB); `train_model.py` fetches it automatically.

## Disclaimer

This project is for **educational and demonstration purposes**. It is a lexical/structural classifier and does not check live page content, certificates, or reputation databases — it should not be relied on as a sole line of defense against phishing.

## License

MIT
=======
# phishing-url-detector
>>>>>>> cbadb925cf89aebd640f39249d61b9ed46f82c9f
