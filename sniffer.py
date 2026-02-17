from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        print("\n==============================")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        # Identify protocol
        if packet.haslayer(TCP):
            print("Protocol: TCP")
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")
        else:
            print("Protocol: Other")

        print("==============================")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)