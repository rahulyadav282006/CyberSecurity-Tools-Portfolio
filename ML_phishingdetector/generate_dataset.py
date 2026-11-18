import random
import pandas as pd

phishing_templates = [
    "Your bank account is suspended. Click {link} immediately to verify password.",
    "Urgent security alert! Confirm your login at {link}",
    "You have won a lottery of $10000. Claim now {link}",
    "Your account will be blocked. Verify details {link}",
    "Suspicious activity detected. Reset password {link}"
]

safe_templates = [
    "Your order has been delivered successfully.",
    "Meeting scheduled tomorrow at 10 AM.",
    "Please find the attached report for review.",
    "Your payment has been received.",
    "Project deadline is next week."
]

links = [
    "http://fake-login.com",
    "http://verify-bank.com",
    "http://security-alert.net"
]

data = []

# Generate phishing emails
for _ in range(5000):
    attachments = [
    "invoice.pdf",
    "payment.exe",
    "receipt.zip",
    "quotation.docm",
    "report.xlsm",
    "invoice.pdf.exe",
    "order.xz"
]

text = random.choice(phishing_templates).format(
    link=random.choice(links)
)

text += "\nAttachment: " + random.choice(attachments)
data.append([text, 1])

# Generate safe emails
for _ in range(5000):
    safe_attachments = [
    "invoice.pdf",
    "payment.pdf",
    "receipt.zip",
    "quotation.doc",
    "report.xlsx",
    "agenda.pdf",
    "minutes.docx",
    "presentation.pptx",
    "budget.xlsx"
    "invoice.pdf",
    "order.xz"
]

    text = random.choice(safe_templates)
    text += "\nAttachment: " + random.choice(safe_attachments)
    data.append([text, 0])

random.shuffle(data)

df = pd.DataFrame(data, columns=["text", "label"])
df.to_csv("dataset.csv", index=False)

print("Dataset generated successfully with", len(df), "records")