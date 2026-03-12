"""
TODO: Could use a lot more checks for malformed packets. They happen in a lot of ways. 

TODO: Over sensitive. Probably from misimplementation. 
"""
from collections import defaultdict
from scapy.all import *
import time
from . import config
import threading

logging.basicConfig(
    filename='HIDS.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def report_log(report):
    print(report)
    logging.warning(report)

def detect_malformed_packet(packet, msg_queue: Queue):

    # First Round : Check if SCAPY can parse, if it cannot, this is a sign of a malformed packet. 
    try:
        if packet.haslayer(IP):
            # Round 2 Checking for invalid internet header length
            if packet[IP].ihl < 5: # Invalid Internet Header Length
                report_log("[!] Malformed IP Header:", packet.summary())
                msg_queue.put(("Malformed Packet Detector", f"[!] Malformed IP Header: {packet.summary()}", ("block_ip", packet[IP].src)))
            
            # Round 3 Check checksums --- Checksum Offloading on the Hardware confuses the checksum detector
            """
            old_checksum = packet[IP].chksum
            del packet[IP].chksum
            new_packet = packet.__class__(bytes(packet))
            if (old_checksum != new_packet[IP].chksum):
                report_log(f"[WARNING] Checksum Mismatch (Malformed Packet): Original Checksum: {old_checksum}, New Checksum: {new_packet[IP].chksum}, {packet.summary()}")
                msg_queue.put(("Malformed Packet Detector", f"[WARNING] Checksum Mismatch (Malformed Packet): Original Checksum: {old_checksum}, New Checksum: {new_packet[IP].chksum}, {packet.summary()}"))
            """
    except Exception as e:
        # Catches packets that fail to parse
        report_log("[WARNING] Malformed packet detected:", e)
        msg_queue.put(("Malformed Packet Detector", f"[WARNING] Malformed Packet Detected: {packet.summary()}"))

def stop_listener(eventflag: threading.Event):
    eventflag.wait()

def run_malformed_packet_sniffer(msg_queue: Queue, eventflag: threading.Event):
    sniffer = AsyncSniffer(iface=get_if_list(), prn=lambda x: detect_malformed_packet(x, msg_queue), store=False)
    sniffer.start()
    listener = threading.Thread(target=stop_listener, args=(eventflag,))
    listener.start()
    listener.join()
    sniffer.stop()