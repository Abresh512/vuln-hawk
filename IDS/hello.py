from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf
from datetime import datetime
from collections import deque, defaultdict
import csv
import time

syn_packets = defaultdict(lambda: deque())

threshhold = 10
windows_size = 10

log_file = "alert.log"
"""
def call_back(packets):
# Print a summary of captured packets
    print(packets.summary()) 

    # Capture 10 packets on a specific interface (e.g., 'eth0' on Linux, 'en0' on macOS)

sniff(iface="eth0", prn=call_back, store=False)
"""


"""from scapy.all import get_if_list

print(get_if_list())"""


"""packet = sniff(iface="eth0", count=20)
wrpcap("captured_packets.pcap", packet)"""

"""log_file = "ip_headers.txt"

iface = conf.iface

def capture_ip(packets):
    if IP in packets:
        src = packets[IP].src
        dst = packets[IP].dst
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sport, dport, proto = "-", "-", "Other"
        if TCP in packets:
            proto = "TCP"
            sport = packets[TCP].sport
            dport = packets[TCP].dport
        elif UDP in packets:
            proto = 'UDP'
            sport = packets[UDP].sport
            dport = packets[UDP].dport
        elif ICMP in packets:
            proto = 'ICMP'
        else:
            proto = 'OTHER'
        log_entry = (f"[{timestamp}] Source ip: {src},Sport:{sport} --> Destination ip: {dst}, Dport:{dport} Protocol {proto} --> IFACE: {iface}\n")

        print(log_entry)


        with open (log_file, "a", newline="") as f:
            f.write(log_entry)"""

"""


csv_file = "ip_headers.csv"


with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "Source ip", "Destination ip"])

def capture_ip(packets):
    if IP in packets:
        src = packets[IP].src
        dst = packets[IP].dst
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (f"[{timestamp}] Source ip: {src} ----> Destination ip: {dst}\n")

        print(log_entry)


        with open (csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src, dst])
"""

def log_alert(message):
    with open(log_file, 'a') as f:
        f.write(message+"\n")


def detect_syn(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        if tcp_layer.flags & 0x02:
            print(f"[syn detected] {ip_layer.src}---> {ip_layer.dst}")
            #ip = packet[IP].src
            ip = ip_layer.src
            now = time.time()
            syn_packets[ip].append(now)

            while syn_packets[ip] and now - syn_packets[ip][0] > windows_size:
                syn_packets[ip].popleft()

            if len(syn_packets[ip]) > threshhold:
                alert = f"[ALERT] Possible SYN flood from {src_ip} at {time.ctime(now)}"
                print(alert)
                log_alert(alert)
            print(f"{ip} -> SYN count in last {windows_size}s: {len(syn_packets[ip])}")

        elif tcp_layer.flags & 0x01:
            print(f"[fin detected] {ip_layer.src}---> {ip_layer.dst}")
        elif tcp_layer.flags & 0x04:
            print(f"[rst detected] {ip_layer.src}---> {ip_layer.dst}")
        elif tcp_layer.flags & 0x08:
            print(f"[psh detected] {ip_layer.src}---> {ip_layer.dst}")
        elif tcp_layer.flags & 0x10:
            print(f"[ack detected] {ip_layer.src}---> {ip_layer.dst}")
        elif tcp_layer.flags & 0x20:
            print(f"[urg detected] {ip_layer.src}---> {ip_layer.dst}")
        else:
            print(f"[no syn] {ip_layer.src}---> {ip_layer.dst}")
       

print("Monitoring....... Press Ctrl+C to stop. ")
sniff(filter="ip", prn=detect_syn, store=0)