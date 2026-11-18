from detector import detect_phishing

def main():
    print("\n🛡️ PHISHING EMAIL DETECTOR")
    print("Paste your email below:\n")

    email_text = ""

    print("Enter email (type END on new line to finish):")

    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        email_text += line + "\n"

    result, score, reasons = detect_phishing(email_text)

    print("\n================ RESULT ================")
    print(f"Status: {result}")
    print(f"Risk Score: {score}")

    print("\nReasons:")
    for r in reasons:
        print(f"- {r}")

    print("=======================================\n")


if __name__ == "__main__":
    main()