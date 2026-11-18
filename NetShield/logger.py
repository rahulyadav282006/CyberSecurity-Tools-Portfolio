import os
from datetime import datetime

LOG_FILE = "logs/events.log"

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

def write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")