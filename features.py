"""
Lexical & structural feature extraction for phishing URL detection.

All features are computed directly from the URL string, so detection is
instant and works fully offline (no WHOIS / DNS / live requests needed).
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "bank", "password", "credential", "wallet", "webscr", "billing",
    "suspend", "unlock", "reset", "support", "recover", "invoice",
    "ebayisapi", "paypal", "security", "alert",
]

SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "shorte.st", "rebrand.ly", "cutt.ly", "tiny.cc",
]

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)

SUSPICIOUS_TLDS = [
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "xyz", "top", "club", "loan", "men", "download",
]


def _ensure_scheme(url: str) -> str:
    if not re.match(r"^[a-zA-Z]+://", url):
        return "http://" + url
    return url


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(raw_url: str) -> dict:
    raw_url = (raw_url or "").strip()
    url = _ensure_scheme(raw_url)
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme
        has_port = int(parsed.port is not None) if parsed.netloc else 0
    except ValueError:
        # Malformed URL (e.g. bad IPv6 brackets) - fall back to naive splitting
        stripped = re.sub(r"^[a-zA-Z]+://", "", url)
        host = stripped.split("/")[0].split(":")[0].lower()
        path = "/" + "/".join(stripped.split("/")[1:]) if "/" in stripped else ""
        query = path.split("?", 1)[1] if "?" in path else ""
        scheme = "https" if url.lower().startswith("https") else "http"
        has_port = 0

    full = raw_url.lower()

    domain_parts = host.split(".") if host else []
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    subdomain_count = max(len(domain_parts) - 2, 0)

    features = {
        "url_length": len(raw_url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_digits": sum(c.isdigit() for c in full),
        "num_params": query.count("=") if query else 0,
        "num_query_components": len(query.split("&")) if query else 0,
        "num_at_symbol": full.count("@"),
        "num_percent": full.count("%"),
        "num_ampersand": full.count("&"),
        "num_equals": full.count("="),
        "has_ip_address": int(bool(IP_PATTERN.match(host))),
        "has_https": int(scheme == "https"),
        "https_in_path": int("https" in path.lower() or "https" in query.lower()),
        "is_shortened": int(any(s in host for s in SHORTENERS)),
        "subdomain_count": subdomain_count,
        "suspicious_word_count": sum(w in full for w in SUSPICIOUS_WORDS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "digit_ratio": (sum(c.isdigit() for c in host) / len(host)) if host else 0.0,
        "hyphen_in_host": int("-" in host),
        "domain_entropy": _shannon_entropy(host),
        "url_entropy": _shannon_entropy(full),
        "tld_length": len(tld),
        "has_port": has_port,
    }
    return features


FEATURE_NAMES = list(extract_features("http://example.com/").keys())
