"""
    Sends NUM_DNS_PACKETS amount of DNS packets to a specified destination ip and port.
    
    Uses random src port and ip
"""

from scapy.all import *
from ipaddress import *
import random

NUM_DNS_PACKETS = 50
DST_IP = "127.0.0.1"

spacket = IP(dst=DST_IP) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="nothing.com"))

# Craft the SYN packet: IP Header / TCP Header (flags="S" for SYN)
for i in range(NUM_DNS_PACKETS):
    spacket[IP].src = str(IPv4Address(random.getrandbits(32)))
    send(spacket, verbose=0)

