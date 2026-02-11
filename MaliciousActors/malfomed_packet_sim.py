"""
TODO: More types of malformed packets
"""

from scapy.all import *

DST_IP = "127.0.0.1"

packet = IP(dst=DST_IP) / TCP(dport=80, chksum=0xffff) # Purposely wrong checksum

send(packet)