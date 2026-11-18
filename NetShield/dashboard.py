import os
import time
from stats import total_packets, alerts, get_top_talker

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def show_dashboard():
    clear_screen()

    top_ip = get_top_talker()

    print("=" * 40)
    print("       NetShield DASHBOARD")
    print("=" * 40)

    print(f"Total Packets : {total_packets}")
    print(f"Alerts Raised  : {alerts}")

    if top_ip:
        print(f"Top IP        : {top_ip}")

    print("\nStatus: MONITORING ACTIVE")
    print("=" * 40)