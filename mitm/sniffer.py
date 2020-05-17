from scapy.all import *
from scapy.utils import *


def print_pkt(pkt):
    try:
        print(pkt.getlayer(Raw).load)
    except:
        pass
    # pkt.show()


pkt = sniff(filter='port 23', prn=print_pkt)
