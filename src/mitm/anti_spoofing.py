import os
import re
import time

from pip._vendor.distlib.compat import raw_input


def check_arp_integrity(list):
    # sending arp table based on a specific interface will check if each MAC address is registered only once
    if len(list) == len(set(list)):
        return False
    else:
        return True


# this program is intended to work on windows
# On UNIX systems the regex might be slightly different to parse MAC and IP addresses
def anti_spoofing(iface="192.168.0.37"):
    print("Running anti-spoofing program on interface {}".format(iface))
    while 1:
        try:
            mac_add = []

            # read each line of ARP table (Windows only)
            with os.popen('arp -a -N {}'.format(iface)) as f:
                data = f.read()

            for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)', data):
                mac = line[1]
                if mac != "ff-ff-ff-ff-ff-ff":
                    mac_add.append(line[1])

            arp_checking = check_arp_integrity(mac_add)

            if arp_checking:
                print("ALERT !!")
                break

            # time between each call, a smaller value can detect the intrusion faster but uses more resources
            time.sleep(1.5)

        except KeyboardInterrupt:
            print("Stopping program..")
            break


def run_antispoof():
    ip = raw_input("[*] Enter IP [192.168.0.37]: ")
    if ip == "":
        ip = "192.168.0.37"
    anti_spoofing(ip)
