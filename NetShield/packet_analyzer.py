from datetime import datetime

packet_history = []

def analyze_packet(packet):
    result = {}

    if packet.haslayer("IP"):
        ip_layer = packet["IP"]

        result = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        packet_history.append(result)

        return result

    return None