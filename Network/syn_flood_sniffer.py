from collections import defaultdict
from scapy.all import *
import time
from . import config
from queue import Queue
import threading

SYN_SRCIP_COUNTS = defaultdict(list)  # {ip: [timestamp1, timestamp2,...]}
SYN_DSTIP_COUNTS = defaultdict(list) 
SRC_THRESHOLD = config.SYN_SRCIP_THRESHOLD # Max SYNs allowed in time window from a specific ip
DST_THRESHOLD = config.SYN_DSTIP_THRESHOLD # Max SYNs allowed in time window to a specific ip
TIME_WINDOW = config.SYN_TIME_WINDOW  # seconds

logging.basicConfig(
    filename='HIDS.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def detect_syn_flood(packet, msg_queue: Queue):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()
        SYN_SRCIP_COUNTS[src].append(now)
        SYN_DSTIP_COUNTS[dst].append(now)
        # Clean old timestamps for destination ips
        SYN_DSTIP_COUNTS[dst] = [t for t in SYN_DSTIP_COUNTS[dst] if now - t < TIME_WINDOW]
        if len(SYN_DSTIP_COUNTS[dst]) > DST_THRESHOLD:
            logging.warning(f"[ALERT] Potential SYN flood on {dst}")
            print(f"[ALERT] Potential SYN flood on {dst}")
            msg_queue.put(("Syn Flood Detector", f"[ALERT] Potential SYN flood on {dst}"))
        # Clean old timestamps for source ips
        SYN_SRCIP_COUNTS[src] = [t for t in SYN_SRCIP_COUNTS[src] if now - t < TIME_WINDOW]
        if len(SYN_SRCIP_COUNTS[src]) > SRC_THRESHOLD:
            logging.warning(f"[ALERT] Potential SYN flood from {src}")
            print(f"[ALERT] Potential SYN flood from {src}")
            msg_queue.put(("Syn Flood Detector", f"[ALERT] Potential SYN flood from {src}"))

def stop_listener(eventflag: threading.Event):
    eventflag.wait()

def run_syn_flood_sniffer(msg_queue: Queue, eventflag: threading.Event):
    sniffer = AsyncSniffer(filter="tcp", iface=get_if_list(), prn=lambda x: detect_syn_flood(x, msg_queue), store=False)
    sniffer.start()
    listener = threading.Thread(target=stop_listener, args=(eventflag,))
    listener.start()
    listener.join()
    sniffer.stop()