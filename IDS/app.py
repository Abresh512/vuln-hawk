from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, conf
from datetime import datetime
from collections import deque, defaultdict
import csv
import time

syn_packets = defaultdict(lambda: deque())

threshhold = 10
windows_size = 10

log_file = "alert.log"
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")



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
                alert = f"[ALERT] Possible SYN flood from {ip} at {time.ctime(now)}"
    

def show_alerts():
    alerts = []
    try:
        with open("alerts.log", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    # split into timestamp, IP, message
                    parts = line.split(",", 2)
                    if len(parts) == 3:
                        alerts.append({
                            "timestamp": part[0],
                            "ip": part[1],
                            "message": part[2]
                        })
    except FileNotFoundError:
        alerts.append({"timestamp":"-", "ip":"-", "message":"No alerts logged yet."})

    return render_template("alerts.html", alerts=alerts)

sniff(filter="ip", prn=detect_syn, store=0)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")