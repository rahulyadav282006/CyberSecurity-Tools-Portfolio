




from scapy.all import sniff
from packet_analyzer import analyze_packet
from detector import detect_threat
from logger import write_log
from stats import update_stats, record_alert

running = True

def process_packet(packet):
    data = analyze_packet(packet)

    if data:
        update_stats(data["src_ip"])

        print(f"{data['src_ip']} -> {data['dst_ip']}")

        threat = detect_threat(data)

        if threat:
            record_alert()
            print("\n🚨 ALERT!")
            print(threat)
            print()

def start_sniffing():
    global running
    running = True

    def process(packet):
        global running

        if not running:
            return

        data = analyze_packet(packet)

        if data:
            update_stats(data["src_ip"])

            print(f"{data['src_ip']} -> {data['dst_ip']}")

            threat = detect_threat(data)

            if threat:
                record_alert()
                print("\n🚨 ALERT!")
                print(threat)
                print()

    sniff(prn=process, store=False)

def stop_sniffing():
    global running
    running = False