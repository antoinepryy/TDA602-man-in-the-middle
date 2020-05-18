from pip._vendor.distlib.compat import raw_input
from scapy.all import *

buffer = []

interface="eth0"

def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def print_pkt(pkt):
    global buffer
    try:
        mac = get_mac("192.168.0.42")
        if (pkt[Ether].src == mac and (pkt.getlayer(Raw) is not None)):
            buffer.append(pkt.getlayer(Raw).load)
            print(buffer)
        #if (pkt[IP].src == "192.168.0.42" and pkt[IP].dst == "192.168.0.43"):
        #pkt.show()
        #print(pkt.getlayer(Raw).load)
    except Exception as e:
        print(e)
    # pkt.show()


#target = input("[*] Enter target IP: ")
#port = input("[*] Enter port: ")
#packet_filter = " IP src {} port {} ".format(target, port)
pkt = sniff(filter='port 23', prn=print_pkt)
