import argparse
import time
import os
import ipaddress
from hosts import host_discovery
from services import syn_scan, services


start = time.time()

# Check if run as root
if os.geteuid() != 0:
    print("Program must be run as root")
    exit()


parser = argparse.ArgumentParser()

parser.add_argument('-m', '--mode',
                    choices=['discover', 'scan'],
                    default='both',
                    help='Host discovery or port scan')

ip = parser.add_mutually_exclusive_group(required=True)

ip.add_argument('-i', '--ip', help="Single IP address")

ip.add_argument('-l', '--list',
                help="List of IP addresses seperated by spaces", nargs='+')

ip.add_argument('-s', '--subnet', help="Subnet")

parser.add_argument(
    '-p', '--ports', help="List of port numbers seperated by spaces",
    type=int, nargs='+')


args = parser.parse_args()

ips = []

if (args.ip):
    try:
        ipaddress.ip_address(args.ip)
        ips.append(args.ip)
    except ValueError:
        print("Invalid IP address", args.ip)


if (args.list):
    for ip in args.list:
        try:
            ipaddress.ip_address(ip)
            ips.append(ip)
        except ValueError:
            print("Invalid IP address", args.ip)

if (args.subnet):
    try:
        network = ipaddress.ip_network(args.subnet)
        ips = [str(ip) for ip in list(network)]
    except ValueError:
        print("Invalid subnet", args.subnet)

if (args.ports):
    ports = args.ports
else:
    ports = list(services.keys())

if (args.mode == "discover"):
    host_discovery(ips)
elif (args.mode == "scan"):
    open_ports = syn_scan(ips, ports)
    for elem in open_ports:
        print("IP:", elem[0], " Port:", elem[1],
              " Service:", services.get(elem[1], "unknown"))
else:
    alive = host_discovery(ips)
    syn_scan(alive, ports)

end = time.time()
print("Scan completed in", str(end-start), "seconds")
