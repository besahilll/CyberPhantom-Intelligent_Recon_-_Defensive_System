from scapy.all import *

def live_nids():
    print("\n[*] Starting Live Network Intrusion Detection System... Press Ctrl+C to stop.")
    def process_packet(pkt):
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == "S":
                print(f"[!] Possible port scan detected from {pkt[IP].src} to {pkt[IP].dst}:{pkt[TCP].dport}")
            elif flags == "FPU":
                print(f"[!] Possible XMAS scan from {pkt[IP].src}")
            elif flags == 0:
                print(f"[!] Null scan from {pkt[IP].src}")
        elif pkt.haslayer(ICMP):
            print(f"[*] ICMP packet from {pkt[IP].src} to {pkt[IP].dst}")

    sniff(filter="ip", prn=process_packet, store=0)

