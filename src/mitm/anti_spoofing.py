import os
import re
import time


def check_arp_integrity(list):
    if len(list) == len(set(list)):
        return False
    else:
        return True


def anti_spoofing(iface="192.168.0.37"):
    while 1:
        try:
            mac_add = []
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
            time.sleep(1.5)

        except KeyboardInterrupt:
            print("Stopping program..")
            break


anti_spoofing()
