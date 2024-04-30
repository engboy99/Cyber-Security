from scapy.all import sniff, Ether, ARP, IP, TCP, UDP

def packet_callback(packet):
    if Ether in packet:
        print("Ethernet Frame:")
        print(f"Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

    if ARP in packet:
        print("ARP Packet:")
        print(f"Sender MAC: {packet[ARP].hwsrc}, Sender IP: {packet[ARP].psrc}")
        print(f"Target MAC: {packet[ARP].hwdst}, Target IP: {packet[ARP].pdst}")

    if IP in packet:
        print("IP Packet:")
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")

    if TCP in packet:
        print("TCP Segment:")
        print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

    if UDP in packet:
        print("UDP Datagram:")
        print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

# Sniffing network traffic
sniff(prn=packet_callback, store=0)
