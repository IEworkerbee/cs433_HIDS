from collections import defaultdict
from scapy.all import *
import time
from queue import Queue
import threading

# This is a thread so I have to do special stuff
# Get the current file's directory
current_dir = os.path.dirname(os.path.realpath(__file__))
# Get the parent directory
parent_dir = os.path.dirname(current_dir)

# Add parent directory to sys.path
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import config

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

def detect_syn_flood(packet, msg_queue: Queue, syn_log):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()
        SYN_SRCIP_COUNTS[src].append(now)
        SYN_DSTIP_COUNTS[dst].append(now)
        syn_log.write(f"{src},{dst},{now}\n")
        # Clean old timestamps for destination ips
        SYN_DSTIP_COUNTS[dst] = [t for t in SYN_DSTIP_COUNTS[dst] if now - t < TIME_WINDOW]
        if len(SYN_DSTIP_COUNTS[dst]) > DST_THRESHOLD:
            logging.warning(f"[ALERT] Potential SYN flood on {dst}")
            print(f"[ALERT] Potential SYN flood on {dst}")
            msg_queue.put(("Syn Flood Detector", f"[ALERT] Potential SYN flood on {dst}", ("block_ip", dst)))
        # Clean old timestamps for source ips
        SYN_SRCIP_COUNTS[src] = [t for t in SYN_SRCIP_COUNTS[src] if now - t < TIME_WINDOW]
        if len(SYN_SRCIP_COUNTS[src]) > SRC_THRESHOLD:
            logging.warning(f"[ALERT] Potential SYN flood from {src}")
            print(f"[ALERT] Potential SYN flood from {src}")
            msg_queue.put(("Syn Flood Detector", f"[ALERT] Potential SYN flood from {src}", ("block_ip", src)))

def stop_listener(eventflag: threading.Event):
    eventflag.wait()

def run_syn_flood_sniffer(msg_queue: Queue, eventflag: threading.Event):
    syn_log = open("syn_log.csv", "w")
    syn_log.write("src,dst,timestamp\n")
    sniffer = AsyncSniffer(filter="tcp", iface=get_if_list(), prn=lambda x: detect_syn_flood(x, msg_queue, syn_log), store=False)
    sniffer.start()
    listener = threading.Thread(target=stop_listener, args=(eventflag,))
    listener.start()
    listener.join()
    sniffer.stop()
    syn_log.close()