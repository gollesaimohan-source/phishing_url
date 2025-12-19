import re

def is_phishing(url):
    suspicious_keywords = [
        "login", "verify", "update", "secure",
        "account", "bank", "free", "bonus"
    ]

    score = 0

    if len(url) > 75:
        score += 1

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 1

    for word in suspicious_keywords:
        if word in url.lower():
            score += 1

    if not url.startswith("https"):
        score += 1

    if score >= 2:
        return {
            "result": "Phishing",
            "risk_score": score
        }
    else:
        return {
            "result": "Safe",
            "risk_score": score
        }
