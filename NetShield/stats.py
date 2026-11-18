from collections import defaultdict

total_packets = 0
alerts = 0

ip_counter = defaultdict(int)

def update_stats(src_ip):
    global total_packets

    total_packets += 1
    ip_counter[src_ip] += 1

def record_alert():
    global alerts
    alerts += 1

def get_top_talker():
    if not ip_counter:
        return None
    return max(ip_counter, key=ip_counter.get)