from scapy.all import *
import socket
import argparse
import time
import os
import ipaddress


def syn_ping(targets: list[str], timeout=0.01):
    print("Performing TCP SYN ping... ")
    time.sleep(1)
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(timeout)
    alive = []
    for target in targets:
        # s.connect((target, 80))
        packet = IP(dst=target) / TCP(dport=80, flags="S")
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            # packet.show()
            # Check if packet source IP is in targets
            if packet.src in targets:
                # print(packet.src, "is alive")
                alive.append(packet.src)
        except socket.timeout:
            continue
        except PermissionError:
            continue
    s.close()
    end = time.time()
    print("Finished. Time elapsed: " + str(end - start) + " seconds")
    return alive


def ack_ping(targets: list[str], timeout=0.01):
    print("Performing TCP ACK ping... ")
    time.sleep(1)
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(timeout)
    alive = []
    for target in targets:
        # s.connect((target, 80))
        packet = IP(dst=target) / TCP(dport=80, flags="A")
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            # packet.show()
            if packet.src in targets:
                # print(packet.src, "is alive")
                alive.append(packet.src)
        except socket.timeout:
            continue
        except PermissionError:
            continue
    s.close()
    end = time.time()
    print("Finished. Time elapsed: " + str(end - start) + " seconds")
    return alive


def icmp_ping(targets: list[str], timeout=0.01):
    print("Performing ICMP ping... ")
    time.sleep(1)
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(timeout)
    alive = []
    for target in targets:
        # s.connect((target, 80))
        packet = IP(dst=target) / ICMP()
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            # packet.show()
            if packet.src in targets:
                # print(packet.src, "is alive")
                alive.append(packet.src)
        except socket.timeout:
            continue
        except PermissionError:
            continue
    s.close()
    end = time.time()
    print("Finished. Time elapsed: " + str(end - start) + " seconds")
    return alive


def host_discovery(targets: list[str], timeout=0.01):
    print("Performing host discovery... ")
    time.sleep(1)
    start = time.time()
    alive = sorted(list(set(syn_ping(targets, timeout) +
                            ack_ping(targets, timeout) +
                            icmp_ping(targets, timeout))))
    for elem in alive:
        print(elem + " is alive")
    end = time.time()
    print("Host discovery complete. Total time elapsed: " +
          str(end - start) + " seconds")
    return alive


services = {21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpc",
            135: "msrpc",
            139: "netbios",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "ms-wbt-server",
            5900: "vnc",
            8080: "http-proxy"}


def syn_scan(targets: list[str], ports: list[int], timeout=0.1):
    print("Performing SYN scan... ")
    time.sleep(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(timeout)
    open_ports = []
    start = time.time()
    for target in targets:
        packets = []
        print("Scanning", target)
        start = time.time()
        # s.connect((target, 80))
        for port in ports:
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            s.sendto(bytes(packet), (target, 0))
            try:
                data = s.recvfrom(1024)
                packet = IP(data[0])
                # packet.show()
                # Check if packet source IP is in targets
                if packet.src == target:
                    packets.append(packet)
            except socket.timeout:
                continue
            except PermissionError:
                continue
        for packet in packets:
            if packet[TCP].flags == 18:
                open_ports.append((target, packet[TCP].sport))
        end = time.time()
        print("Finished. Time elapsed: " + str(end - start) + " seconds")
    s.close()
    end = time.time()
    print("Total time elapsed: " + str(end - start) + " seconds")
    print("Open ports: ")
    for elem in open_ports:
        print("IP:", elem[0], " Port:", elem[1],
              " Service:", services.get(elem[1], "unknown"))


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
