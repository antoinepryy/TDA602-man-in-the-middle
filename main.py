import argparse
import sys

from src.mitm.mitm import mitm
from src.mitm.sniffer import sniffer

parser = argparse.ArgumentParser()
parser.add_argument("action", help="what do you want me to do ?", choices=("sniffer", "telnet", "ARP"))
args = parser.parse_args()
print(args.action)

if args.action == "sniffer":
    sniffer()

elif args.action == "telnet":
    print("Not yet implemented..")
    sys.exit(1)

elif args.action == "ARP":
    mitm()
