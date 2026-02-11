from collections import defaultdict
from scapy.all import *
import time
import config
import logging

DNS_SRCIP_COUNTS = defaultdict(list)  # {ip: [timestamp1, timestamp2,...]}
DNS_DSTIP_COUNTS = defaultdict(list) 
SRC_THRESHOLD = config.DNS_SRCIP_THRESHOLD # Max DNSs allowed in time window from a specific ip
DST_THRESHOLD = config.DNS_DSTIP_THRESHOLD # Max DNSs allowed in time window to a specific ip
TIME_WINDOW = config.DNS_TIME_WINDOW  # seconds

logging.basicConfig(
    filename='HIDS.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def detect_dns_flood(packet):
    try:
        packet.show()
    except Exception as e:
        logging.warning(f"[WARNING] Malformed packet detected: {e}")
        print(f"[WARNING] Malformed packet detected: {e}")

    if packet.haslayer(DNS) and packet.haslayer(IP) and packet[IP].dport == 53:
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()
        DNS_SRCIP_COUNTS[src].append(now)
        DNS_DSTIP_COUNTS[dst].append(now)
        # Clean old timestamps for destination ips
        DNS_DSTIP_COUNTS[dst] = [t for t in DNS_DSTIP_COUNTS[dst] if now - t < TIME_WINDOW]
        if len(DNS_DSTIP_COUNTS[dst]) > DST_THRESHOLD:
            print(f"[ALERT] Potential DNS flood on {dst}")
            logging.warning(f"[ALERT] Potential DNS flood on {dst}")
        # Clean old timestamps for source ips
        DNS_SRCIP_COUNTS[src] = [t for t in DNS_SRCIP_COUNTS[src] if now - t < TIME_WINDOW]
        if len(DNS_SRCIP_COUNTS[src]) > SRC_THRESHOLD:
            print(f"[ALERT] Potential DNS flood from {src}")
            logging.warning(f"[ALERT] Potential DNS flood from {src}")

sniff(filter="udp port 53", iface=get_if_list(), prn=detect_dns_flood, store=False)