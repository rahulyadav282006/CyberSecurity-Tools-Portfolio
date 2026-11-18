from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
   
    # Create an ARP request packet (pdst=target IP range)
    arp_request = ARP(pdst=ip_range)
  

    
    # Create an Ethernet frame (broadcast to all devices on the network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine Ethernet frame + ARP request
    packet = ether / arp_request
  

    
    # Send the packet and capture responses (timeout=3 seconds)
    # srp() returns a list of (sent_packet, received_packet) pairs
    result = srp(packet, timeout=3, verbose=0)[0]
    


    # Parse responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

if __name__ == "__main__":
    # Define the IP range to scan (e.g., "192.168.1.1/24" scans 192.168.1.1-254)
    target_ip = "10.77.19.0/24" # Replace with your subnet
    devices = scan_network(target_ip)
    
    # Print results
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")