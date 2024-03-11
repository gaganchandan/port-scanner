from scapy.all import *
import socket
import argparse
import time
import os
import ipaddress


filename = "output.txt"
file = open(filename, "w")


def syn_ping(targets: list[str], timeout=0.01):
    print("Performing TCP SYN ping... ")
    time.sleep(1)
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(timeout)
    alive = []
    for target in targets:
        packet = IP(dst=target) / TCP(dport=80, flags="S")
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            if packet.src in targets:
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
        packet = IP(dst=target) / TCP(dport=80, flags="A")
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            if packet.src in targets:
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
        packet = IP(dst=target) / ICMP()
        try:
            s.sendto(bytes(packet), (target, 0))
            data = s.recvfrom(1024)
            packet = IP(data[0])
            if packet.src in targets:
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
    end = time.time()
    print("Host discovery complete. Total time elapsed: " +
          str(end - start) + " seconds")
    print()
    print()
    print("*******************************************************************************")
    print("LIVE HOSTS")
    print("*******************************************************************************")
    for elem in alive:
        print(elem)
    print("*******************************************************************************")
    print("*******************************************************************************")
    print()
    print()
    file.write("\n\nLIVE HOSTS:\n")
    for elem in alive:
        print(elem, file=file)
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
            8080: "http-proxy",
            }


def syn_scan(targets: list[str], ports: list[int], timeout=0.1):
    print("Performing SYN scan...\n")
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
        for port in ports:
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            s.sendto(bytes(packet), (target, 0))
            try:
                data1 = s.recvfrom(1024)
                data2 = s.recvfrom(1024)
                data3 = s.recvfrom(1024)
                for data in [data1, data2, data3]:
                    packet = IP(data[0])
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
        print("Finished. Time elapsed: " + str(end - start) + " seconds\n")
    s.close()
    end = time.time()
    print("Total time elapsed: " + str(end - start) + " seconds\n")
    print("*******************************************************************************")
    print("OPEN PORTS")
    print("*******************************************************************************")
    for elem in open_ports:
        print("IP:", elem[0], " | Port:", elem[1],
              " | Service:", services.get(elem[1], "unknown"))
    print("*******************************************************************************")
    print("*******************************************************************************")
    print()
    print()
    file.write("\n\nOPEN PORTS:\n")
    for elem in open_ports:
        print("IP:", elem[0], " | Port:", elem[1],
              " | Service:", services.get(elem[1], "unknown"), file=file)
    return open_ports


def http_scan(targets: list[str], ports: list[int], timeout=0.1):
    print("Identifying HTTP ports...\n")
    time.sleep(1)
    found = []
    for target in targets:
        print("Scanning", target)
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        for port in ports:
            try:
                s.connect((target, port))
                s.send(b"GET / HTTP/1.1\r\n\r\n")
                data1 = s.recvfrom(1024)
                data2 = s.recvfrom(1024)
                data3 = s.recvfrom(1024)
                for data in [data1, data2, data3]:
                    if "HTTP" in str(data[0]):
                        found.append((target, port))
            except:
                continue
        s.close()
        end = time.time()
        print("Finished. Time elapsed: " + str(end - start) + " seconds\n")
    print("*******************************************************************************")
    print("HTTP SERVICES")
    print("*******************************************************************************")
    for elem in found:
        print("HTTP service found at", elem[0], "on port", elem[1])
    print("*******************************************************************************")
    print("*******************************************************************************")
    print()
    print()
    file.write("\n\nHTTP SERVICES:\n")
    for elem in found:
        print("HTTP service found at", elem[0], "on port", elem[1], file=file)


start = time.time()

if os.geteuid() != 0:
    print("Program must be run as root")
    exit()

banner = \
    """
*******************************************************************************
*******************************************************************************

 _____   ____  _____ _______    _____  _____          _   _ _   _ ______ _____
|  __ \\ / __ \\|  __ |__   __|  / ____|/ ____|   /\\   | \\ | | \\ | |  ____|  __ \\
| |__) | |  | | |__) | | |    | (___ | |       /  \\  |  \\| |  \\| | |__  | |__) |
|  ___/| |  | |  _  /  | |     \\___ \\| |      / /\\ \\ | . ` | . ` |  __| |  _  /
| |    | |__| | | \\ \\  | |     ____) | |____ / ____ \\| |\\  | |\\  | |____| | \\ \\
|_|     \\____/|_|  \\_\\ |_|    |_____/ \\_____/_/    \\_|_| \\_|_| \\_|______|_|  \\_\\


*******************************************************************************
*******************************************************************************
"""

print(banner)

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

port = parser.add_mutually_exclusive_group(required=False)

port.add_argument(
    '-p', '--ports', help="List of port numbers seperated by spaces",
    type=int, nargs='+')
port.add_argument(
    '-r' '--range', help='Range of ports specified by lower and upper bounds seperated by a space', nargs=2, type=int
)


args = parser.parse_args()

ips = []

if (args.ip):
    try:
        ipaddress.ip_address(args.ip)
        ips.append(args.ip)
        file.write("IP address: " + args.ip + "\n")
    except ValueError:
        print("Invalid IP address", args.ip)
        exit()


if (args.list):
    for ip in args.list:
        try:
            ipaddress.ip_address(ip)
            ips.append(ip)
        except ValueError:
            print("Invalid IP address", args.ip)
            exit()
        file.write("IP addresses:\n")
        for ip in args.list:
            print(ip + "\n", file=file)

if (args.subnet):
    try:
        network = ipaddress.ip_network(args.subnet)
        ips = [str(ip) for ip in list(network)]
        file.write("Subnet: " + args.subnet + "\n")
    except ValueError:
        print("Invalid subnet", args.subnet)
        exit()


if (args.ports):
    ports = args.ports
elif (args.r__range):
    ports = list(range(args.r__range[0], args.r__range[1]+1))
else:
    ports = list(services.keys())

if (args.mode == "discover"):
    host_discovery(ips)
elif (args.mode == "scan"):
    open_ports = syn_scan(ips, ports)
    for elem in open_ports:
        http_scan([elem[0]], [elem[1]])

else:
    alive = host_discovery(ips)
    open_ports = syn_scan(alive, ports)
    for elem in open_ports:
        http_scan([elem[0]], [elem[1]])

end = time.time()
print("Scan completed in", str(end-start), "seconds")
