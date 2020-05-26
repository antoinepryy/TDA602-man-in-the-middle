import argparse

from src.mitm.anti_spoofing import run_antispoof
from src.mitm.mitm import mitm
from src.mitm.sniffer_http import run as sniff_http
from src.mitm.sniffer_telnet import run as sniff_telnet

parser = argparse.ArgumentParser()
parser.add_argument("action", help="what do you want me to do ?",
                    choices=("telnet", "http", "ARP", "defense"))
args = parser.parse_args()

if args.action == "telnet":
    sniff_telnet()

elif args.action == "http":
    sniff_http()

elif args.action == "ARP":
    mitm()

elif args.action == "defense":
    run_antispoof()
