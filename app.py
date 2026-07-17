"""
Phishing URL Detection - Flask web application.

Loads a pre-trained RandomForest model and serves real-time predictions
on URLs submitted through the web UI or the JSON API.
"""

import os
import joblib
import pandas as pd
from flask import Flask, render_template, request, jsonify

from features import extract_features, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")

app = Flask(__name__)

_bundle = None


def get_model():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "Model not found. Run `python model/train_model.py` first."
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


# Human-readable labels + short explanations for the top contributing features,
# shown in the UI so the result isn't just a black-box score.
FEATURE_EXPLANATIONS = {
    "has_ip_address": "URL uses a raw IP address instead of a domain name",
    "suspicious_word_count": "Contains words commonly used in phishing (login, verify, secure...)",
    "is_shortened": "Uses a URL shortening service, hiding the real destination",
    "num_hyphens": "Number of hyphens in the URL",
    "hyphen_in_host": "Hyphen present in the domain name",
    "has_https": "Connection is served over HTTPS",
    "subdomain_count": "Number of subdomains",
    "suspicious_tld": "Uses a top-level domain often abused for phishing",
    "domain_entropy": "Randomness of characters in the domain name",
    "url_entropy": "Randomness of characters across the full URL",
    "num_at_symbol": "Contains '@', which can be used to obscure the real host",
    "url_length": "Overall length of the URL",
    "num_digits": "Number of digits in the URL",
    "digit_ratio": "Proportion of digits in the domain name",
    "path_length": "Length of the URL path",
    "host_length": "Length of the domain name",
    "num_dots": "Number of dots in the URL",
    "num_slashes": "Number of slashes in the URL",
    "num_underscores": "Number of underscores in the URL",
    "num_params": "Number of query-string parameters",
    "num_query_components": "Number of query-string components",
    "num_percent": "Number of percent-encoded characters",
    "num_equals": "Number of '=' characters in the URL",
    "num_ampersand": "Number of '&' characters in the URL",
    "tld_length": "Length of the top-level domain",
    "has_port": "URL explicitly specifies a network port",
    "https_in_path": "'https' appears in the path/query rather than the scheme, often used to fake legitimacy",
}


def analyze_url(url: str) -> dict:
    bundle = get_model()
    model = bundle["model"]
    feature_names = bundle["feature_names"]

    feats = extract_features(url)
    X = pd.DataFrame([feats], columns=feature_names)

    proba = model.predict_proba(X)[0]
    phishing_proba = float(proba[1])
    prediction = "phishing" if phishing_proba >= 0.5 else "legit"

    # Rank the features by (importance * value) contribution for this URL
    importances = model.feature_importances_
    contributions = []
    for name, imp in zip(feature_names, importances):
        val = feats[name]
        if val:  # only show features that actually fired
            contributions.append({
                "name": name,
                "value": val,
                "importance": round(float(imp), 4),
                "explanation": FEATURE_EXPLANATIONS.get(name),
            })
    contributions.sort(key=lambda c: c["importance"], reverse=True)

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": round(phishing_proba * 100, 2),
        "legit_probability": round((1 - phishing_proba) * 100, 2),
        "features": feats,
        "top_signals": contributions[:6],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL to analyze."}), 400
    try:
        result = analyze_url(url)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(result)


@app.route("/health")
def health():
    try:
        get_model()
        return jsonify({"status": "ok", "model_loaded": True})
    except FileNotFoundError as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
