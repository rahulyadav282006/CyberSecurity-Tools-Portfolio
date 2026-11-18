import pickle
import re

# Load model and vectorizer
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# Dangerous attachment types
DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".jar",
    ".com",
    ".ps1",
    ".docm",
    ".xlsm",
    ".zip",
    ".rar",
    ".xz"
]


def preprocess_email(email_text):
    email = email_text.lower()

    # Detect URLs
    urls = re.findall(r"http[s]?://\S+", email)
    if urls:
        email += " HAS_URL"

    # Detect email addresses
    emails = re.findall(r"\S+@\S+", email)
    if emails:
        email += " HAS_EMAIL"

    # Detect dangerous attachments
    for ext in DANGEROUS_EXTENSIONS:
        if ext in email:
            email += " DANGEROUS_ATTACHMENT"

    # Detect attachment keyword
    if "attachment:" in email:
        email += " HAS_ATTACHMENT"

    return email


def predict_email(email_text):

    processed_email = preprocess_email(email_text)

    # Rule-based detection
    if "dangerous_attachment" in processed_email.lower():
        return "PHISHING"

    # ML Prediction
    vector = vectorizer.transform([processed_email])

    prediction = model.predict(vector)[0]

    if prediction == 1:
        return "PHISHING"
    else:
        return "SAFE"