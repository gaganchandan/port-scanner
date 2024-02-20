from scapy.all import *
import socket
import time


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
