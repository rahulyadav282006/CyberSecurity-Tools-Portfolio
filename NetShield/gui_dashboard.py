import tkinter as tk
import threading
from packet_capture import start_sniffing, stop_sniffing
from stats import total_packets, alerts, get_top_talker

running = False
sniff_thread = None


class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("NetShield IDS Control Panel")
        self.root.geometry("450x350")
        self.root.configure(bg="black")

        # Title
        tk.Label(root, text="NetShield IDS", fg="lime", bg="black",
                 font=("Arial", 16, "bold")).pack(pady=10)

        # Labels
        self.packet_label = tk.Label(root, fg="white", bg="black")
        self.packet_label.pack()

        self.alert_label = tk.Label(root, fg="red", bg="black")
        self.alert_label.pack()

        self.ip_label = tk.Label(root, fg="cyan", bg="black")
        self.ip_label.pack()

        self.status_label = tk.Label(root, fg="yellow", bg="black", font=("Arial", 12, "bold"))
        self.status_label.pack(pady=10)

        # Buttons
        tk.Button(root, text="START MONITORING", bg="green", fg="white",
                  command=self.start_system).pack(pady=5)

        tk.Button(root, text="STOP MONITORING", bg="red", fg="white",
                  command=self.stop_system).pack(pady=5)

        self.update_dashboard()

    def start_system(self):
        global running, sniff_thread

        if not running:
            running = True
            sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
            sniff_thread.start()

    def stop_system(self):
        global running
        running = False
        stop_sniffing()

    def update_dashboard(self):
        top_ip = get_top_talker()

        self.packet_label.config(text=f"Total Packets: {total_packets}")
        self.alert_label.config(text=f"Alerts: {alerts}")

        if top_ip:
            self.ip_label.config(text=f"Top IP: {top_ip}")

        if alerts == 0:
            status = "SAFE"
            color = "green"
        elif alerts < 5:
            status = "WARNING"
            color = "yellow"
        else:
            status = "THREAT"

        self.status_label.config(text=f"Status: {status}", fg=color)

        self.root.after(2000, self.update_dashboard)


def run_gui():
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()