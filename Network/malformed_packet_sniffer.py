"""
TODO: Could use a lot more checks for malformed packets. They happen in a lot of ways. 

TODO: Over sensitive. Probably from misimplementation. 
"""
from collections import defaultdict
from scapy.all import *
import time
import config

logging.basicConfig(
    filename='HIDS.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def detect_malformed_packet(packet):
    if packet.haslayer(IP):
        old_checksum = packet[IP].chksum
        del packet[IP].chksum
        new_packet = IP(raw(packet[IP]))
        if (old_checksum != new_packet[IP].chksum):
            logging.warning(f"[WARNING] Checksum Mismatch (Malformed Packet): {packet.summary()}")
            print(f"[WARNING] Checksum Mismatch (Malformed Packet): {packet.summary()}")


sniff(iface=get_if_list(), prn=detect_malformed_packet, store=False)