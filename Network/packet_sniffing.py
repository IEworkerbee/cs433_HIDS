from scapy.all import *
from collections import defaultdict
import time
import config

SYN_SRCIP_COUNTS = defaultdict(list)  # {ip: [timestamp1, timestamp2,...]}
SYN_DSTIP_COUNTS = defaultdict(list) 
SRC_THRESHOLD = config.SYN_SRCIP_THRESHOLD # Max SYNs allowed in time window from a specific ip
DST_THRESHOLD = config.SYN_DSTIP_THRESHOLD # Max SYNs allowed in time window to a specific ip
TIME_WINDOW = config.SYN_TIME_WINDOW  # seconds

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()
        SYN_SRCIP_COUNTS[src].append(now)
        SYN_DSTIP_COUNTS[dst].append(now)
        # Clean old timestamps for destination ips
        SYN_DSTIP_COUNTS[dst] = [t for t in SYN_DSTIP_COUNTS[dst] if now - t < TIME_WINDOW]
        if len(SYN_DSTIP_COUNTS[dst]) > DST_THRESHOLD:
            print(f"[ALERT] Potential SYN flood on {dst}")
        # Clean old timestamps for source ips
        SYN_SRCIP_COUNTS[src] = [t for t in SYN_SRCIP_COUNTS[src] if now - t < TIME_WINDOW]
        if len(SYN_SRCIP_COUNTS[src]) > SRC_THRESHOLD:
            print(f"[ALERT] Potential SYN flood from {src}")

sniff(filter="tcp", iface=get_if_list(), prn=detect_syn_flood, store=False)