from collections import defaultdict
from scapy.all import *
import time
from . import config
import logging
import threading

DNS_SRCIP_COUNTS = defaultdict(list)  # {ip: [timestamp1, timestamp2,...]}
DNS_DSTIP_COUNTS = defaultdict(list) 
SRC_THRESHOLD = config.DNS_SRCIP_THRESHOLD # Max DNSs allowed in time window from a specific ip
DST_THRESHOLD = config.DNS_DSTIP_THRESHOLD # Max DNSs allowed in time window to a specific ip
TIME_WINDOW = config.DNS_TIME_WINDOW  # seconds

logging.basicConfig(
    filename='network.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)



def detect_dns_flood(packet, msg_queue: Queue, dns_log):
    if packet.haslayer(DNS) and packet.haslayer(IP) and packet[IP].dport == 53:
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()
        DNS_SRCIP_COUNTS[src].append(now)
        DNS_DSTIP_COUNTS[dst].append(now)
        # Clean old timestamps for destination ips
        dns_log.write(f"{src},{dst},{now}\n")
        DNS_DSTIP_COUNTS[dst] = [t for t in DNS_DSTIP_COUNTS[dst] if now - t < TIME_WINDOW]
        if len(DNS_DSTIP_COUNTS[dst]) > DST_THRESHOLD:
            print(f"[ALERT] Potential DNS flood on {dst}")
            logging.warning(f"[ALERT] Potential DNS flood on {dst}")
            msg_queue.put(("DNS Flood Detector", f"[ALERT] Potential DNS flood on {dst}", ("block_ip", dst)))
        # Clean old timestamps for source ips
        DNS_SRCIP_COUNTS[src] = [t for t in DNS_SRCIP_COUNTS[src] if now - t < TIME_WINDOW]
        if len(DNS_SRCIP_COUNTS[src]) > SRC_THRESHOLD:
            print(f"[ALERT] Potential DNS flood from {src}")
            logging.warning(f"[ALERT] Potential DNS flood from {src}")
            msg_queue.put(("DNS Flood Detector", f"[ALERT] Potential DNS flood from {src}", ("block_ip", src)))

def stop_listener(eventflag: threading.Event):
    eventflag.wait()

def run_dns_flood_sniffer(msg_queue: Queue, eventflag: threading.Event):
    dns_log = open("dns_log.csv", "w")
    dns_log.write("src,dst,timestamp\n")
    sniffer = AsyncSniffer(filter="udp port 53", iface=get_if_list(),  prn=lambda x: detect_dns_flood(x, msg_queue, dns_log), store=False)
    sniffer.start()
    listener = threading.Thread(target=stop_listener, args=(eventflag,))
    listener.start()
    listener.join()
    sniffer.stop()
    dns_log.close()