from scapy.all import *


# broadcasting on private network a packet containing ARP protocol of the target allow to have its MAC address
def get_mac(IP, interface="eth0"):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
