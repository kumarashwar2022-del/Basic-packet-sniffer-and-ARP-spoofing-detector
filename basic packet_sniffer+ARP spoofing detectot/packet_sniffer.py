from scapy.all import *

tcp_count = 0
udp_count = 0
icmp_count = 0

def process_packet(packet):

    global tcp_count, udp_count, icmp_count

    if packet.haslayer(IP):

        print(f"\nSource: {packet[IP].src}")
        print(f"Destination: {packet[IP].dst}")

        if packet.haslayer(TCP):
            tcp_count += 1
            print("Protocol: TCP")

        elif packet.haslayer(UDP):
            udp_count += 1
            print("Protocol: UDP")

        elif packet.haslayer(ICMP):
            icmp_count += 1
            print("Protocol: ICMP")

        print(f"TCP={tcp_count} UDP={udp_count} ICMP={icmp_count}")

print("Packet Sniffer Started...")
print("Press Ctrl + C to Stop")

sniff(prn=process_packet, store=False)