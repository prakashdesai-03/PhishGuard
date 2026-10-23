"""
PhishGuard: Explainable Phishing URL and Scam Message Detection System
=======================================================================
IBM SkillsBuild Cyber Security 2026 — BharatCares
Author  : Prakash Desai
Version : 1.0.0
License : Educational / Non-commercial

Run:
    python PrakashDesai_PhishGuard.py

Then open http://127.0.0.1:5000 in your browser.
"""

# ── Standard library ──────────────────────────────────────────────────────────
import os
import re
import json
import math
import string
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from collections import Counter

# ── Third-party ───────────────────────────────────────────────────────────────
from flask import (Flask, render_template, request, jsonify,
                   session, send_file, abort)
from markupsafe import escape
import joblib
import numpy as np

# ── Optional heavy deps ───────────────────────────────────────────────────────
try:
    import pandas as pd
    PANDAS_OK = True
except ImportError:
    PANDAS_OK = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_score,
                                  recall_score, f1_score,
                                  classification_report)
    from sklearn.preprocessing import LabelEncoder
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

# ═══════════════════════════════════════════════════════════════════════════════
# APP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "models", "phish_rf_model.joblib")
DATA_DIR    = os.path.join(BASE_DIR, "data")
DATASET_CSV = os.path.join(DATA_DIR, "phishing_urls.csv")

app = Flask(__name__)
app.secret_key = os.urandom(24)           # ephemeral — restart clears session
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024   # 1 MB request limit

# ── In-memory session stats (not persisted to disk) ───────────────────────────
_session_stats: dict = {
    "total_scans": 0,
    "url_scans": 0,
    "msg_scans": 0,
    "risk_counts": {"Low": 0, "Medium": 0, "High": 0, "Unknown": 0},
    "recent": [],          # last 10 scan summaries (no raw message content)
}

_ml_model        = None   # loaded lazily
_ml_metrics: dict = {}    # populated after training


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE A — URL FEATURE EXTRACTION & RULE-BASED SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# Common legitimate TLDs used in typosquatting detection
COMMON_BRANDS = [
    "paypal", "amazon", "google", "facebook", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "ebay", "yahoo",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc",
    "sbi", "icici", "hdfc", "paytm", "phonepe", "gpay", "upi",
    "flipkart", "myntra", "swiggy", "zomato",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".download", ".loan", ".work", ".date", ".racing", ".win",
    ".stream", ".gdn", ".bid", ".trade", ".review", ".science",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "rebrand.ly", "short.io", "cutt.ly", "tr.im",
}


def _entropy(s: str) -> float:
    """Shannon entropy of a string — high entropy ≈ random/encoded content."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> dict:
    """
    Extract numeric and boolean features from a URL string.
    Returns a feature dict used both for rule-based scoring and ML inference.
    All extraction is purely lexical — no DNS, no HTTP requests.
    """
    url = url.strip()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    hostname    = parsed.hostname or ""
    path        = parsed.path or ""
    query       = parsed.query or ""
    full_url    = url

    # ── basic counts ──────────────────────────────────────────────────────────
    url_length           = len(full_url)
    hostname_length      = len(hostname)
    path_length          = len(path)
    num_dots_hostname    = hostname.count(".")
    num_dots_url         = full_url.count(".")
    num_hyphens          = full_url.count("-")
    num_underscores      = full_url.count("_")
    num_slashes          = full_url.count("/")
    num_at               = full_url.count("@")
    num_question         = full_url.count("?")
    num_ampersand        = full_url.count("&")
    num_equals           = full_url.count("=")
    num_percent          = full_url.count("%")
    num_digits_url       = sum(c.isdigit() for c in full_url)
    num_digits_host      = sum(c.isdigit() for c in hostname)

    # ── structural flags ─────────────────────────────────────────────────────
    uses_https           = int(parsed.scheme == "https")
    has_ip_host          = _is_ip_address(hostname)
    has_at_symbol        = int("@" in full_url)
    has_double_slash     = int("//" in path)
    has_hex_encoding     = int(bool(re.search(r"%[0-9a-fA-F]{2}", full_url)))
    has_port             = int(parsed.port is not None and parsed.port not in (80, 443))
    has_suspicious_tld   = int(any(hostname.endswith(t) for t in SUSPICIOUS_TLDS))
    is_url_shortener     = int(hostname in URL_SHORTENERS or
                               any(hostname.endswith("." + s) for s in URL_SHORTENERS))
    subdomain_count      = max(0, num_dots_hostname - 1)
    has_brand_in_subdomain = int(_brand_in_subdomain(hostname))
    has_redirect_word    = int(bool(re.search(
        r"(redirect|goto|click|go|forward|out|link|url|ref)",
        full_url, re.I)))
    has_login_word       = int(bool(re.search(
        r"(login|logon|signin|sign-in|account|verify|secure|update|confirm)",
        full_url, re.I)))
    entropy_hostname     = _entropy(hostname)
    entropy_path         = _entropy(path)
    ratio_digits_url     = num_digits_url / max(url_length, 1)

    return dict(
        url_length=url_length,
        hostname_length=hostname_length,
        path_length=path_length,
        num_dots_hostname=num_dots_hostname,
        num_dots_url=num_dots_url,
        num_hyphens=num_hyphens,
        num_underscores=num_underscores,
        num_slashes=num_slashes,
        num_at=num_at,
        num_question=num_question,
        num_ampersand=num_ampersand,
        num_equals=num_equals,
        num_percent=num_percent,
        num_digits_url=num_digits_url,
        num_digits_host=num_digits_host,
        uses_https=uses_https,
        has_ip_host=has_ip_host,
        has_at_symbol=has_at_symbol,
        has_double_slash=has_double_slash,
        has_hex_encoding=has_hex_encoding,
        has_port=has_port,
        has_suspicious_tld=has_suspicious_tld,
        is_url_shortener=is_url_shortener,
        subdomain_count=subdomain_count,
        has_brand_in_subdomain=has_brand_in_subdomain,
        has_redirect_word=has_redirect_word,
        has_login_word=has_login_word,
        entropy_hostname=entropy_hostname,
        entropy_path=entropy_path,
        ratio_digits_url=ratio_digits_url,
    )


def _is_ip_address(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def _brand_in_subdomain(hostname: str) -> bool:
    parts = hostname.split(".")
    if len(parts) < 3:
        return False
    subdomain = ".".join(parts[:-2]).lower()
    return any(b in subdomain for b in COMMON_BRANDS)


# ── Rule-based warning engine ─────────────────────────────────────────────────

def rule_based_url_analysis(url: str) -> dict:
    """
    Analyse a URL using transparent rule-based heuristics.
    Returns warnings, score, risk level, and recommended actions.
    Does NOT make network requests.
    """
    url   = url.strip()
    if not url:
        return {"error": "Empty URL provided."}

    # Reject clearly non-URL strings
    if len(url) > 2048:
        return {"error": "URL exceeds maximum length of 2048 characters."}

    feats   = extract_url_features(url)
    parsed  = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""

    warnings = []
    score    = 0   # 0–100; higher = more suspicious

    # ── individual checks ────────────────────────────────────────────────────

    if not feats["uses_https"]:
        warnings.append({
            "code": "NO_HTTPS",
            "severity": "medium",
            "text": "URL uses HTTP instead of HTTPS.",
            "explanation": (
                "Unencrypted connections expose your data in transit. "
                "Legitimate services almost always use HTTPS — though "
                "HTTPS alone does not guarantee safety."
            ),
        })
        score += 10

    if feats["has_ip_host"]:
        warnings.append({
            "code": "IP_HOST",
            "severity": "high",
            "text": f"Hostname is an IP address ({hostname}).",
            "explanation": (
                "Legitimate websites use domain names. "
                "IP-address URLs are commonly used in phishing to avoid "
                "domain reputation checks."
            ),
        })
        score += 30

    if feats["url_length"] > 100:
        warnings.append({
            "code": "LONG_URL",
            "severity": "medium",
            "text": f"Unusually long URL ({feats['url_length']} characters).",
            "explanation": (
                "Phishing URLs are often padded with extra parameters or "
                "subdomains to confuse users and hide the real domain."
            ),
        })
        score += 10

    if feats["has_at_symbol"]:
        warnings.append({
            "code": "AT_SYMBOL",
            "severity": "high",
            "text": "URL contains '@' symbol.",
            "explanation": (
                "Browsers treat everything before '@' as credentials and "
                "navigate to the real host after it. Attackers use this to "
                "make a URL appear legitimate."
            ),
        })
        score += 30

    if feats["subdomain_count"] >= 3:
        warnings.append({
            "code": "EXCESS_SUBDOMAINS",
            "severity": "medium",
            "text": f"Excessive subdomains detected ({feats['subdomain_count']}).",
            "explanation": (
                "Multiple subdomains can be used to embed recognizable brand "
                "names early in the URL while hiding the actual registered domain."
            ),
        })
        score += 15

    if feats["has_brand_in_subdomain"]:
        warnings.append({
            "code": "BRAND_SUBDOMAIN",
            "severity": "high",
            "text": "A known brand name appears in the subdomain, not the registered domain.",
            "explanation": (
                "Attackers register domains like paypal.attacker.com — the brand "
                "appears in the subdomain but the actual domain is different."
            ),
        })
        score += 25

    if feats["num_hyphens"] >= 4:
        warnings.append({
            "code": "MANY_HYPHENS",
            "severity": "low",
            "text": f"Many hyphens in URL ({feats['num_hyphens']}).",
            "explanation": (
                "Multiple hyphens are sometimes used in lookalike domains, "
                "e.g., pay-pal-secure-login.com."
            ),
        })
        score += 8

    if feats["has_hex_encoding"]:
        warnings.append({
            "code": "HEX_ENCODING",
            "severity": "medium",
            "text": "URL contains percent-encoded (hex) characters.",
            "explanation": (
                "Hex encoding can be used to obscure suspicious keywords or "
                "characters from simple content filters."
            ),
        })
        score += 12

    if feats["has_suspicious_tld"]:
        warnings.append({
            "code": "SUSPICIOUS_TLD",
            "severity": "medium",
            "text": f"Domain uses a TLD associated with high abuse rates.",
            "explanation": (
                "Certain free or low-cost TLDs (.tk, .ml, .xyz, etc.) appear "
                "disproportionately often in phishing campaigns."
            ),
        })
        score += 15

    if feats["is_url_shortener"]:
        warnings.append({
            "code": "URL_SHORTENER",
            "severity": "medium",
            "text": "URL appears to be from a URL-shortening service.",
            "explanation": (
                "Short URLs hide the destination. Attackers use them to mask "
                "malicious links. Expand the URL before visiting."
            ),
        })
        score += 12

    if feats["has_double_slash"]:
        warnings.append({
            "code": "DOUBLE_SLASH",
            "severity": "low",
            "text": "URL path contains '//'.",
            "explanation": (
                "Double slashes in paths are sometimes used to confuse "
                "URL parsers or security filters."
            ),
        })
        score += 5

    if feats["has_login_word"] and not feats["uses_https"]:
        warnings.append({
            "code": "LOGIN_NO_HTTPS",
            "severity": "high",
            "text": "URL mentions login/account without HTTPS.",
            "explanation": (
                "Login pages that do not use HTTPS transmit credentials in "
                "plain text, which is a serious risk."
            ),
        })
        score += 20

    if feats["entropy_hostname"] > 3.8:
        warnings.append({
            "code": "HIGH_ENTROPY_HOST",
            "severity": "low",
            "text": "Hostname has high character entropy — may be randomly generated.",
            "explanation": (
                "Domain generation algorithms (DGAs) create random-looking "
                "hostnames. High entropy can indicate such automation."
            ),
        })
        score += 8

    if feats["has_port"]:
        warnings.append({
            "code": "NON_STANDARD_PORT",
            "severity": "medium",
            "text": f"Non-standard port ({parsed.port}) used.",
            "explanation": (
                "Legitimate sites rarely use non-standard ports in shared URLs. "
                "This may indicate a local proxy, test server, or obfuscation."
            ),
        })
        score += 10

    # ── risk categorisation ──────────────────────────────────────────────────
    score = min(score, 100)
    risk_level, risk_color = _score_to_risk(score)

    # ── recommended actions ───────────────────────────────────────────────────
    actions = _build_url_actions(risk_level, feats, warnings)

    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "path": parsed.path,
        "query": parsed.query,
        "features": feats,
        "warnings": warnings,
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "warning_count": len(warnings),
        "actions": actions,
        "disclaimer": (
            "This analysis is heuristic-based. No warnings does not mean "
            "the URL is safe. Always verify the registered domain independently."
        ),
    }


def _score_to_risk(score: int) -> tuple[str, str]:
    if score == 0:
        return "Low",    "success"
    if score < 25:
        return "Low",    "success"
    if score < 55:
        return "Medium", "warning"
    return "High", "danger"


def _build_url_actions(risk_level: str, feats: dict, warnings: list) -> list[str]:
    actions = []
    codes   = {w["code"] for w in warnings}
    if risk_level == "High":
        actions.append("Do NOT enter credentials or personal information on this page.")
        actions.append("Close the page immediately and report it.")
    if "IP_HOST" in codes:
        actions.append("Never trust websites identified only by an IP address.")
    if "AT_SYMBOL" in codes:
        actions.append("Treat this URL as highly suspicious — do not click it.")
    if "BRAND_SUBDOMAIN" in codes:
        actions.append("Check the registered domain (last two parts) — ignore the subdomain.")
    if "URL_SHORTENER" in codes:
        actions.append("Expand the URL first at a service like checkshorturl.com before visiting.")
    if "NO_HTTPS" in codes:
        actions.append("Avoid submitting any form data over an unencrypted HTTP connection.")
    if not actions:
        actions.append("No critical indicators found, but always verify the domain carefully.")
        actions.append("Check the SSL certificate owner before entering sensitive information.")
    actions.append("When in doubt, navigate directly to the official website instead of clicking links.")
    return actions


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE B — SCAM MESSAGE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

SCAM_PATTERNS = [
    {
        "code": "OTP_REQUEST",
        "pattern": r"\b(otp|one[\s\-]time[\s\-]password|verification\s+code)\b",
        "severity": "high",
        "text": "Request for OTP or verification code.",
        "explanation": (
            "Legitimate services NEVER ask for your OTP via message. "
            "Anyone asking for your OTP is attempting fraud."
        ),
    },
    {
        "code": "PASSWORD_REQUEST",
        "pattern": r"\b(password|passcode|pin\b|secret\s+key)\b",
        "severity": "high",
        "text": "Request for password or PIN.",
        "explanation": (
            "No legitimate bank, service, or support team needs your password. "
            "Sharing it gives full account access to attackers."
        ),
    },
    {
        "code": "URGENT_ACTION",
        "pattern": r"\b(urgent|immediate(?:ly)?|act\s+now|within\s+24\s+hours?|expire[ds]?\s+soon|last\s+chance|final\s+warning)\b",
        "severity": "high",
        "text": "Artificially created urgency.",
        "explanation": (
            "Scammers manufacture time pressure to prevent victims from "
            "pausing and thinking critically."
        ),
    },
    {
        "code": "ACCOUNT_SUSPEND",
        "pattern": r"\b(account\s+(will\s+be\s+)?(suspended|blocked|disabled|closed|terminated))\b",
        "severity": "high",
        "text": "Threat of account suspension or closure.",
        "explanation": (
            "Threatening suspension is a classic social engineering tactic "
            "to force hasty, uncritical responses."
        ),
    },
    {
        "code": "PRIZE_REWARD",
        "pattern": r"\b(you\s+have\s+(won|been\s+selected)|congratulations.*prize|cash\s+prize|lottery|lucky\s+(winner|draw))\b",
        "severity": "high",
        "text": "Prize, lottery, or reward claim.",
        "explanation": (
            "Unexpected prize offers are almost always fraudulent. "
            "They typically lead to fee or credential theft."
        ),
    },
    {
        "code": "FAKE_PAYMENT",
        "pattern": r"\b(payment\s+(of\s+)?(rs\.?|inr|usd|\$|₹)\s*[\d,]+|refund\s+credited|cashback\s+pending|transaction\s+failed)\b",
        "severity": "medium",
        "text": "Fake payment notification.",
        "explanation": (
            "Fraudulent payment notifications lure victims into clicking links "
            "or calling back numbers that steal credentials."
        ),
    },
    {
        "code": "VERIFY_LINK",
        "pattern": r"\b(click\s+(here|the\s+link|below)|verify\s+(your|account|identity)|confirm\s+(your|account))\b",
        "severity": "medium",
        "text": "Invitation to click a verification link.",
        "explanation": (
            "Links in unsolicited messages frequently lead to phishing pages. "
            "Go directly to the official website instead."
        ),
    },
    {
        "code": "SENSITIVE_INFO",
        "pattern": r"\b(bank\s+(account|details?)|credit\s+card\s+(number|details?)|cvv|aadhaar|pan\s+card|ssn|social\s+security)\b",
        "severity": "high",
        "text": "Request for sensitive financial or identity information.",
        "explanation": (
            "Legitimate organisations never solicit full card numbers, "
            "CVVs, Aadhaar numbers, or SSNs via message."
        ),
    },
    {
        "code": "DELIVERY_SCAM",
        "pattern": r"\b(package\s+(on\s+hold|detained)|delivery\s+(failed|pending)|customs\s+fee|parcel\s+notice)\b",
        "severity": "medium",
        "text": "Fake delivery or courier notification.",
        "explanation": (
            "Fake delivery messages direct victims to phishing sites that "
            "collect payment card details under the guise of release fees."
        ),
    },
    {
        "code": "IMPERSONATION",
        "pattern": r"\b(from\s+(?:rbi|sebi|income\s+tax|irs|fbi|cbi|police|microsoft|apple|amazon|google|paypal)\b)",
        "severity": "high",
        "text": "Possible impersonation of authority or major brand.",
        "explanation": (
            "Scammers impersonate government bodies and well-known companies "
            "to add apparent legitimacy. Always verify through official channels."
        ),
    },
    {
        "code": "EMBEDDED_URL",
        "pattern": r"https?://\S+",
        "severity": "medium",
        "text": "Embedded URL found in message.",
        "explanation": (
            "URLs in unsolicited messages may lead to phishing sites. "
            "Verify any URL before clicking."
        ),
    },
    {
        "code": "KYC_SCAM",
        "pattern": r"\b(kyc\s+(update|pending|expir|verif)|complete\s+your\s+kyc)\b",
        "severity": "high",
        "text": "KYC update request.",
        "explanation": (
            "Fraudsters claim your KYC is pending and direct you to fake "
            "banking portals. Banks initiate KYC through official in-branch "
            "or secure in-app processes."
        ),
    },
]


def analyze_message(text: str) -> dict:
    """
    Analyse message text for scam indicators using transparent pattern matching.
    Does not store message content.
    """
    if not text or not text.strip():
        return {"error": "Empty message provided."}
    if len(text) > 5000:
        return {"error": "Message exceeds maximum length of 5000 characters."}

    text_lower = text.lower()
    matched    = []

    for pat in SCAM_PATTERNS:
        if re.search(pat["pattern"], text_lower, re.I):
            matched.append({
                "code":        pat["code"],
                "severity":    pat["severity"],
                "text":        pat["text"],
                "explanation": pat["explanation"],
            })

    # Score
    severity_weight = {"high": 25, "medium": 12, "low": 5}
    score = min(sum(severity_weight.get(m["severity"], 5) for m in matched), 100)
    risk_level, risk_color = _score_to_risk(score)

    # Embedded URL analysis
    urls_found = re.findall(r"https?://\S+", text, re.I)
    url_analyses = []
    for u in urls_found[:3]:          # limit to first 3 URLs
        url_analyses.append(rule_based_url_analysis(u.rstrip(".,;)\"'")))

    actions = _build_message_actions(risk_level, matched)

    return {
        "indicators":     matched,
        "score":          score,
        "risk_level":     risk_level,
        "risk_color":     risk_color,
        "indicator_count": len(matched),
        "urls_found":     urls_found,
        "url_analyses":   url_analyses,
        "actions":        actions,
        "disclaimer": (
            "Pattern-matching may produce false positives. "
            "A clean result does not guarantee the message is legitimate."
        ),
    }


def _build_message_actions(risk_level: str, indicators: list) -> list[str]:
    actions = []
    codes   = {i["code"] for i in indicators}
    if risk_level == "High":
        actions.append("Do NOT respond to or act on this message.")
        actions.append("Do NOT click any links or call numbers in the message.")
    if "OTP_REQUEST" in codes or "PASSWORD_REQUEST" in codes:
        actions.append("Never share OTPs, passwords, or PINs with anyone.")
    if "IMPERSONATION" in codes:
        actions.append("Call the official helpline number of the organisation to verify.")
    if "EMBEDDED_URL" in codes:
        actions.append("Copy the URL and paste it into our URL Scanner before visiting.")
    if "PRIZE_REWARD" in codes:
        actions.append("If you did not enter a contest, you cannot have won. Ignore and delete.")
    if risk_level in ("High", "Medium"):
        actions.append("Report the message to your national cybercrime portal.")
        actions.append("Block the sender and do not forward the message.")
    if not actions:
        actions.append("No major indicators found, but stay cautious with unsolicited messages.")
    return actions


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE C — MACHINE LEARNING PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

ML_FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length",
    "num_dots_hostname", "num_dots_url", "num_hyphens",
    "num_underscores", "num_slashes", "num_at",
    "num_question", "num_ampersand", "num_equals",
    "num_percent", "num_digits_url", "num_digits_host",
    "uses_https", "has_ip_host", "has_at_symbol",
    "has_double_slash", "has_hex_encoding", "has_port",
    "has_suspicious_tld", "is_url_shortener", "subdomain_count",
    "has_brand_in_subdomain", "has_redirect_word",
    "has_login_word", "entropy_hostname", "entropy_path",
    "ratio_digits_url",
]


def load_dataset(csv_path: str = DATASET_CSV) -> "pd.DataFrame | None":
    """
    Load and preprocess the phishing URL dataset.

    Expected schema (LegitPhish — Mendeley Data v2):
        url   : string
        label : 0 = legitimate, 1 = phishing  (or 'phishing'/'legitimate')

    Returns a cleaned DataFrame or None if unavailable.
    """
    if not PANDAS_OK:
        return None
    if not os.path.isfile(csv_path):
        return None

    df = pd.read_csv(csv_path, low_memory=False)

    # Normalise column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Identify URL column
    url_col = next((c for c in df.columns if "url" in c), None)
    if url_col is None:
        return None

    # Identify label column
    label_col = next(
        (c for c in df.columns if c in ("label", "type", "class", "status", "result")),
        None,
    )
    if label_col is None:
        return None

    df = df[[url_col, label_col]].copy()
    df.rename(columns={url_col: "url", label_col: "label"}, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(subset="url", inplace=True)

    # Normalise labels to 0/1
    if df["label"].dtype == object:
        le = LabelEncoder()
        df["label"] = le.fit_transform(df["label"].str.strip().str.lower())
        # Ensure phishing = 1 (lexicographically 'phishing' > 'legitimate')
    else:
        df["label"] = df["label"].astype(int)

    df = df[df["label"].isin([0, 1])].reset_index(drop=True)

    # Sample to at most 100 000 rows for training speed
    if len(df) > 100_000:
        df = df.sample(100_000, random_state=42).reset_index(drop=True)

    return df


def _features_from_df(df: "pd.DataFrame") -> "np.ndarray":
    rows = []
    for url in df["url"]:
        feats = extract_url_features(str(url))
        rows.append([feats.get(col, 0) for col in ML_FEATURE_COLUMNS])
    return np.array(rows, dtype=float)


def train_model(csv_path: str = DATASET_CSV) -> dict:
    """
    Train a Random Forest classifier on the phishing URL dataset.
    Saves the model to MODEL_PATH.
    Returns a metrics dict.
    """
    global _ml_model, _ml_metrics

    if not SKLEARN_OK:
        return {"error": "scikit-learn is not installed."}
    if not PANDAS_OK:
        return {"error": "pandas is not installed."}

    df = load_dataset(csv_path)
    if df is None or len(df) < 100:
        return {"error": "Dataset not available or too small. "
                         "Place phishing_urls.csv in the data/ folder."}

    X = _features_from_df(df)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    y_pred   = clf.predict(X_test)
    accuracy  = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall    = float(recall_score(y_test, y_pred, zero_division=0))
    f1        = float(f1_score(y_test, y_pred, zero_division=0))

    _ml_model   = clf
    _ml_metrics = {
        "accuracy":  round(accuracy,  4),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
        "train_size": int(len(X_train)),
        "test_size":  int(len(X_test)),
        "trained_at": datetime.now(timezone.utc).isoformat() + "Z",
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)

    return _ml_metrics


def load_model() -> bool:
    """Load a previously saved model. Returns True on success."""
    global _ml_model
    if not SKLEARN_OK:
        return False
    if os.path.isfile(MODEL_PATH):
        try:
            _ml_model = joblib.load(MODEL_PATH)
            return True
        except Exception:
            return False
    return False


def ml_predict(url: str) -> dict:
    """
    Run the ML model on a URL.
    Returns prediction, confidence, and feature importances.
    Falls back gracefully if model is unavailable.
    """
    if _ml_model is None:
        return {
            "available": False,
            "message": "ML model not loaded. Use the 'Train Model' page to train it.",
        }
    feats  = extract_url_features(url)
    X      = np.array([[feats.get(col, 0) for col in ML_FEATURE_COLUMNS]])
    pred   = int(_ml_model.predict(X)[0])
    proba  = _ml_model.predict_proba(X)[0]
    conf   = float(proba[pred])

    importances = {}
    if hasattr(_ml_model, "feature_importances_"):
        for name, imp in zip(ML_FEATURE_COLUMNS, _ml_model.feature_importances_):
            importances[name] = round(float(imp), 4)
        # top 5
        top5 = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
    else:
        top5 = []

    return {
        "available":   True,
        "prediction":  pred,
        "label":       "Phishing" if pred == 1 else "Legitimate",
        "confidence":  round(conf * 100, 1),
        "top_features": top5,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE D — UNIFIED RISK ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════════════

def unified_url_scan(url: str) -> dict:
    """Combine rule-based and ML results into a single risk assessment."""
    rule  = rule_based_url_analysis(url)
    if "error" in rule:
        return rule

    ml    = ml_predict(url)

    # Blend scores: rule-based 70 %, ML 30 % when available
    final_score = rule["score"]
    if ml.get("available") and ml["prediction"] == 1:
        boost       = int((ml["confidence"] / 100) * 30)
        final_score = min(final_score + boost, 100)

    risk_level, risk_color = _score_to_risk(final_score)

    return {
        **rule,
        "ml":          ml,
        "final_score": final_score,
        "risk_level":  risk_level,
        "risk_color":  risk_color,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE E — REPORT EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

def build_scan_report(data: dict) -> str:
    """Return a plain-text report for a URL or message scan result."""
    lines = [
        "PhishGuard Analysis Report",
        "=" * 50,
        f"Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Scan type : {data.get('scan_type', 'URL')}",
        "",
    ]
    if "url" in data:
        lines += [f"URL       : {data['url']}",
                  f"Hostname  : {data.get('hostname', '')}",
                  f"Scheme    : {data.get('scheme', '')}",
                  ""]
    lines += [
        f"Risk Level: {data.get('risk_level', 'Unknown')}",
        f"Score     : {data.get('final_score', data.get('score', '—'))}/100",
        "",
        "── Warnings / Indicators ──",
    ]
    for w in data.get("warnings", data.get("indicators", [])):
        lines.append(f"  [{w['severity'].upper()}] {w['text']}")
        lines.append(f"         {w['explanation']}")
    lines += ["", "── Recommended Actions ──"]
    for a in data.get("actions", []):
        lines.append(f"  • {a}")
    lines += ["", data.get("disclaimer", ""), ""]
    ml = data.get("ml", {})
    if ml.get("available"):
        lines += [
            "── ML Prediction ──",
            f"  Label      : {ml['label']}",
            f"  Confidence : {ml['confidence']}%",
            "",
        ]
    lines.append("=" * 50)
    lines.append("DISCLAIMER: PhishGuard is a heuristic tool for educational use.")
    lines.append("It is NOT a substitute for professional security software.")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.before_request
def _init_session():
    pass


def _update_stats(scan_type: str, risk_level: str, summary: str):
    _session_stats["total_scans"] += 1
    if scan_type == "url":
        _session_stats["url_scans"] += 1
    else:
        _session_stats["msg_scans"] += 1
    rl = risk_level if risk_level in _session_stats["risk_counts"] else "Unknown"
    _session_stats["risk_counts"][rl] += 1
    _session_stats["recent"].insert(0, {
        "type": scan_type,
        "risk": risk_level,
        "summary": summary[:80],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
    })
    _session_stats["recent"] = _session_stats["recent"][:10]


# ── Page routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", stats=_session_stats)


@app.route("/url-scanner")
def url_scanner_page():
    return render_template("url_scanner.html")


@app.route("/message-analyzer")
def message_analyzer_page():
    return render_template("message_analyzer.html")


@app.route("/model-performance")
def model_performance_page():
    return render_template("model_performance.html",
                           metrics=_ml_metrics,
                           model_loaded=(_ml_model is not None))


@app.route("/security-tips")
def security_tips_page():
    return render_template("security_tips.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    data = request.get_json(silent=True) or {}
    url  = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long."}), 400

    result = unified_url_scan(url)
    if "error" not in result:
        _update_stats("url", result.get("risk_level", "Unknown"),
                      f"URL: {url[:60]}")
    result["scan_type"] = "URL"
    return jsonify(result)


@app.route("/api/scan-message", methods=["POST"])
def api_scan_message():
    data    = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "No message provided."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message too long (max 5000 chars)."}), 400

    result = analyze_message(message)
    if "error" not in result:
        _update_stats("message", result.get("risk_level", "Unknown"),
                      f"Message ({len(message)} chars)")
    result["scan_type"] = "Message"
    return jsonify(result)


@app.route("/api/train-model", methods=["POST"])
def api_train_model():
    if not SKLEARN_OK or not PANDAS_OK:
        return jsonify({"error": "ML dependencies unavailable."}), 503
    metrics = train_model()
    if "error" in metrics:
        return jsonify(metrics), 503
    return jsonify({"success": True, "metrics": metrics})


@app.route("/api/stats")
def api_stats():
    return jsonify(_session_stats)


@app.route("/api/export-report", methods=["POST"])
def api_export_report():
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No data provided."}), 400
    report_text = build_scan_report(data)
    import io
    buf = io.BytesIO(report_text.encode("utf-8"))
    buf.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"phishguard_report_{ts}.txt",
        mimetype="text/plain",
    )


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Request too large."}), 413


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500,
                           message="Internal server error."), 500


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "data"),   exist_ok=True)
    load_model()   # attempt to load pre-trained model on startup
    print("=" * 60)
    print("  PhishGuard — IBM SkillsBuild Cyber Security 2026")
    print("  Author: Prakash Desai")
    print(f"  ML model loaded: {_ml_model is not None}")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 60)
    app.run(debug=False, host="127.0.0.1", port=5000)
