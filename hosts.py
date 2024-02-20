from scapy.all import *
import socket
import time


# TCP SYN ping
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
