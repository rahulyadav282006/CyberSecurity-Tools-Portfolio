import re

# List of phishing keywords
PHISHING_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "password",
    "login",
    "blocked",
    "suspended",
    "click here",
    "bank",
    "security alert"
]


def detect_phishing(email_text):
    score = 0
    reasons = []

    text = email_text.lower()

    matched_keywords = set()

    for word in PHISHING_KEYWORDS:
        if word in text:
            matched_keywords.add(word)

    if matched_keywords:
        score += len(matched_keywords) * 2
        for word in matched_keywords:
            reasons.append(f"Suspicious keyword detected: {word}")

    # link check
    if "http" in text:
        score += 3
        reasons.append("Contains external links")

    # sensitive info check
    if "password" in text:
        score += 3
        reasons.append("Requests sensitive information")

    # cap score
    score = min(score, 15)

    if score <= 3:
        result = "SAFE"
        if not reasons:
            reasons.append("Email structure is clean and no phishing indicators found .")
    elif score <= 7:
        result = "SUSPICIOUS"
    else:
        result = "PHISHING"

    return result, score, reasons