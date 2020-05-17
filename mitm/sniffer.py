from pip._vendor.distlib.compat import raw_input
from scapy.all import *

username = ""
password = ""


def print_pkt(pkt):
    try:
        print(pkt.getlayer(Raw).load)
    except:
        pass
    # pkt.show()


target = raw_input("[*] Enter target IP: ")
port = raw_input("[*] Enter port: ")
packet_filter = "IP src {} port {}".format(target, port)
print(packet_filter)
pkt = sniff(filter=packet_filter, prn=print_pkt)
