from collections import defaultdict
import time

ip_packet_count = defaultdict(int)
ip_targets = defaultdict(set)
ip_last_seen = {}

THRESHOLD_PACKETS = 20
THRESHOLD_PORTS = 10
TIME_WINDOW = 10  # seconds
last_alert_time = {}
ALERT_COOLDOWN = 5  # seconds

def detect_threat(packet_data):
    src = packet_data["src_ip"]
    current_time = time.time()

    # cooldown check
    if src in last_alert_time:
        if current_time - last_alert_time[src] < ALERT_COOLDOWN:
            return None

    ip_packet_count[src] += 1
    ip_targets[src].add(packet_data["dst_ip"])

    # High traffic rule
    if ip_packet_count[src] > THRESHOLD_PACKETS:
        last_alert_time[src] = current_time
        return {
            "threat": "HIGH TRAFFIC",
            "ip": src,
            "reason": "Too many packets in short time"
        }

    # Port scan rule
    if len(ip_targets[src]) > THRESHOLD_PORTS:
        last_alert_time[src] = current_time
        return {
            "threat": "PORT SCANNING",
            "ip": src,
            "reason": "Multiple destinations detected"
        }

    return None