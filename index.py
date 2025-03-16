from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = "xxx.xxx.xxx.xxx"  # Masked source IP
        ip_dst = "xxx.xxx.xxx.xxx"  # Masked Destination IP
        proto = packet[IP].proto
        
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {proto}")

sniff(filter="ip", prn=packet_callback, store=0)

# I cannot share the real IP address