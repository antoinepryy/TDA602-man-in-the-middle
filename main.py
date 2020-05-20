import argparse
import sys

from src.mitm.anti_spoofing import run_antispoof
from src.mitm.mitm import mitm
from src.mitm.sniffer import sniffer

parser = argparse.ArgumentParser()
parser.add_argument("action", help="what do you want me to do ?", choices=("sniffer", "telnet", "ARP", "defense"))
args = parser.parse_args()

if args.action == "sniffer":
    sniffer()

elif args.action == "telnet":
    print("Not yet implemented..")
    sys.exit(1)

elif args.action == "ARP":
    mitm()

elif args.action == "defense":
    run_antispoof()
