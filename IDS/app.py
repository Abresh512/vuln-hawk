from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")

def detect_syn(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        if tcp_layer.flags & 0x02:
            ip = ip_layer.src
            now = time.time()
            syn_packets[ip].append(now)

            while syn_packets[ip] and now - syn_packets[ip][0] > windows_size:
                syn_packets[ip].popleft()

            if len(syn_packets[ip]) > threshhold:
                alert = f"[ALERT] Possible SYN flood from {src_ip} at {time.ctime(now)}"
                log_alert(alert)
                ip_addrs = (f"{ip_layer.src}---> {ip_layer.dst}")



def show_alerts(packet):
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
                            "timestamp": now,
                            "ip": ip_addrs,
                            "message": alert
                        })
    except FileNotFoundError:
        alerts.append({"timestamp":"-", "ip":"-", "message":"No alerts logged yet."})

    return render_template("alerts.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
