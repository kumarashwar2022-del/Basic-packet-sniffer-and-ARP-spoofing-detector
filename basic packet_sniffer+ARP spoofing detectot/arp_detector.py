from scapy.all import *
from datetime import datetime

arp_table = {}

def log_alert(message):
    with open("logs.txt", "a") as file:
        file.write(message + "\n")

def detect_arp(packet):

    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        print(f"IP: {ip} -> MAC: {mac}")

        if ip in arp_table:

            if arp_table[ip] != mac:

                timestamp = datetime.now()

                alert = (
                    f"[ALERT] {timestamp} | "
                    f"IP: {ip} | "
                    f"Old MAC: {arp_table[ip]} | "
                    f"New MAC: {mac}"
                )

                print(alert)

                log_alert(alert)

        arp_table[ip] = mac

print("ARP Spoofing Detector Started...")
print("Press Ctrl + C to Stop")
log_alert("[INFO] ARP Detector Started Sucessfully")

sniff(filter="arp", prn=detect_arp, store=False)