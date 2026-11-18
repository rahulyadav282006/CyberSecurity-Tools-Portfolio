from detector import predict_email

print("🛡️ ML PHISHING EMAIL DETECTOR")

print("\nPaste email (type END to finish):")

email = ""

while True:
    line = input()
    if line.strip().upper() == "END":
        break
    email += line + "\n"

result = predict_email(email)

print("\n================ RESULT ================")
print("Status:", result)
print("=======================================\n")