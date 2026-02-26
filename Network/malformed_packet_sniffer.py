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

def report_log(err_name, summary):
    report = f"{err_name} {summary}"
    print(report)
    logging.warning(report)

def detect_malformed_packet(packet):

    # First Round : Check if SCAPY can parse, if it cannot, this is a sign of a malformed packet. 
    try:
        if packet.haslayer(IP):
            # Round 2 Checking for invalid internet header length
            if packet[IP].ihl < 5: # Invalid Internet Header Length
                report_log("[!] Malformed IP Header:", packet.summary())
            
            # Round 3 Check checksums
            old_checksum = packet[IP].chksum
            del packet[IP].chksum
            new_packet = IP(raw(packet[IP]))
            if (old_checksum != new_packet[IP].chksum):
                report_log("[WARNING] Checksum Mismatch (Malformed Packet):", packet.summary())

    except Exception as e:
        # Catches packets that fail to parse
        report_log("[WARNING] Malformed packet detected:", e)


sniff(iface=get_if_list(), prn=detect_malformed_packet, store=False)