# # app.py
# from collections import defaultdict, deque, Counter
# from scapy.all import sniff, TCP, IP
# from flask import Flask, render_template, jsonify
# import threading
# import time
# import os
# import datetime

# app = Flask(__name__)

# # ---------- Config ----------
# WINDOW_SECONDS = 10         # window for SYN detection
# THRESHOLD = 10              # SYN threshold to trigger alert
# ALERT_SUPPRESS_SECONDS = 30 # suppress repeated alert for same IP for this many seconds
# ACTIVE_WINDOW = 30          # seconds: an IP is "active" if seen within this many seconds
# ALERT_LOG = "alerts.log"
# SYN_KEYWORDS = ("syn", "syn flood", "syn scan", "tcp:flags=syn", "syn-ack")
# # ----------------------------

# # Data structures (shared between sniff thread and Flask)
# syn_packets = defaultdict(lambda: deque())  # syn_packets[src_ip] -> deque of timestamps
# last_alert_time = {}                        # last_alert_time[src_ip] = unix_time
# last_seen = {}                              # last_seen[ip] = unix_time
# packet_counts = Counter()                   # packet_counts[ip] = total packets seen

# _lock = threading.Lock()                    # protect shared structures

# def log_alert_line(ts_iso, ip, message):
#     """Append a single-line CSV alert: timestamp,ip,message"""
#     line = f"{ts_iso},{ip},{message}\n"
#     with open(ALERT_LOG, "a") as f:
#         f.write(line)

# def detect_packet(packet):
#     """
#     Called for each captured packet (sniff callback).
#     - updates last_seen and packet_counts for source and dest IPs
#     - detects SYNs and writes alerts if thresholds exceeded
#     """
#     try:
#         if not packet.haslayer(IP):
#             return

#         now = time.time()
#         ip_layer = packet[IP]
#         src = ip_layer.src
#         dst = ip_layer.dst

#         # update last seen & counts for both source and dest
#         with _lock:
#             last_seen[src] = now
#             last_seen[dst] = now
#             packet_counts[src] += 1
#             packet_counts[dst] += 1

#         # SYN detection (only for TCP)
#         if packet.haslayer(TCP):
#             tcp_layer = packet[TCP]
#             # check SYN flag (0x02)
#             if tcp_layer.flags & 0x02:
#                 with _lock:
#                     dq = syn_packets[src]
#                     dq.append(now)
#                     # pop old timestamps outside sliding window
#                     while dq and (now - dq[0]) > WINDOW_SECONDS:
#                         dq.popleft()

#                     # if count above threshold and not recently alerted, log it
#                     if len(dq) > THRESHOLD:
#                         last = last_alert_time.get(src, 0)
#                         if now - last > ALERT_SUPPRESS_SECONDS:
#                             ts_iso = datetime.datetime.utcfromtimestamp(now).replace(microsecond=0).isoformat()
#                             msg = f"SYN flood suspected to {dst} ({len(dq)} SYNs in {WINDOW_SECONDS}s)"
#                             log_alert_line(ts_iso, src, msg)
#                             last_alert_time[src] = now
#                             print(f"[ALERT] {src} -> {dst}: {msg}")
#     except Exception as e:
#         print("detect_packet error:", e)


# def start_sniff_thread(iface=None):
#     """
#     Start scapy sniff in a daemon thread so Flask can also run.
#     Uses BPF "ip" to capture IPv4 packets (includes TCP/UDP/ICMP).
#     """
#     def _sniff():
#         sniff(filter="ip", prn=detect_packet, store=False, iface=iface)

#     t = threading.Thread(target=_sniff, daemon=True)
#     t.start()
#     return t


# # ---------- Helpers for Flask to read data ----------

# def parse_alerts_file(path=ALERT_LOG):
#     """
#     return (alerts_list, syn_counter)
#     alerts_list: list of dicts {timestamp, ip, message, is_syn}
#     syn_counter: Counter of syn alerts per IP (counts messages containing SYN keywords)
#     """
#     alerts = []
#     syn_counter = Counter()
#     if not os.path.exists(path):
#         return alerts, syn_counter

#     with open(path, "r") as f:
#         for line in f:
#             line = line.strip()
#             if not line:
#                 continue
#             parts = line.split(",", 2)
#             if len(parts) != 3:
#                 continue
#             timestamp, ip, message = parts[0].strip(), parts[1].strip(), parts[2].strip()
#             lower_msg = message.lower()
#             is_syn = any(k in lower_msg for k in SYN_KEYWORDS)
#             alerts.append({
#                 "timestamp": timestamp,
#                 "ip": ip,
#                 "message": message,
#                 "is_syn": is_syn
#             })
#             if is_syn:
#                 syn_counter[ip] += 1

#     alerts.reverse()
#     return alerts, syn_counter

# def get_active_ips(window=ACTIVE_WINDOW, top_n=50):
#     """
#     Return list of tuples (ip, last_seen_iso, age_seconds, packet_count),
#     sorted by most recent last_seen, limited to top_n.
#     """
#     now = time.time()
#     with _lock:
#         items = []
#         for ip, ts in last_seen.items():
#             age = now - ts
#             if age <= window:
#                 iso = datetime.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat()
#                 cnt = packet_counts.get(ip, 0)
#                 items.append((ip, iso, int(age), cnt))
#     # sort by most recent (smallest age)
#     items.sort(key=lambda x: x[2])
#     return items[:top_n]


# # ---------- Flask routes ----------
# @app.route("/")
# def show_alerts():
#     alerts, syn_counter = parse_alerts_file()
#     top_offenders = syn_counter.most_common(10)
#     active = get_active_ips()
#     return render_template("alerts.html", alerts=alerts, top_offenders=top_offenders, active_ips=active)

# @app.route("/alerts.json")
# def alerts_json():
#     alerts, _ = parse_alerts_file()
#     return jsonify(alerts)

# @app.route("/active.json")
# def active_json():
#     active = get_active_ips()
#     # convert to dicts for JSON
#     out = [{"ip":ip,"last_seen":last_seen_iso,"age_s":age,"count":count} for ip,last_seen_iso,age,count in active]
#     return jsonify(out)


# if __name__ == "__main__":
#     iface = os.environ.get("IFACE", None)
#     print("Starting sniff thread on iface:", iface or "default (scapy chooses)")
#     start_sniff_thread(iface=iface)
#     app.run(debug=True, host="0.0.0.0", port=5000)


from flask import Flask, render_template
from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import threading
import time

app = Flask(__name__)

# ---------------- IDS DATA STRUCTURES ----------------
syn_packets = defaultdict(lambda: deque())
baseline_rate = defaultdict(lambda: 0)
last_checked = defaultdict(lambda: time.time())
active_ips = defaultdict(lambda: time.time())

WINDOW = 10                 # 10-second sliding window
BASELINE_INTERVAL = 60      # recalculate baseline every 60 sec
THRESHOLD_MULTIPLIER = 5    # alert if SYN rate exceeds 5× baseline
ACTIVE_IP_TIMEOUT = 30      # consider IP "active" if seen within 30 sec

# ---------------- IDS LOG FUNCTION ----------------
def log_alert(ip, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("alerts.log", "a") as f:
        f.write(f"{timestamp},{ip},{message}\n")

# ---------------- DETECTION FUNCTION ----------------
def detect_syn(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]
        src_ip = ip.src
        now = time.time()

        # Track all active IPs
        active_ips[src_ip] = now

        # SYN packet detection
        if tcp.flags & 0x02:  # SYN flag
            syn_packets[src_ip].append(now)

            # Remove old SYNs outside window
            while syn_packets[src_ip] and now - syn_packets[src_ip][0] > WINDOW:
                syn_packets[src_ip].popleft()

            syn_rate = len(syn_packets[src_ip]) / WINDOW

            # Update baseline
            if now - last_checked[src_ip] > BASELINE_INTERVAL:
                baseline_rate[src_ip] = (baseline_rate[src_ip] + syn_rate) / 2
                last_checked[src_ip] = now

            # Compare to baseline
            baseline = baseline_rate[src_ip] or 5  # default baseline
            if syn_rate > baseline * THRESHOLD_MULTIPLIER:
                alert_msg = f"Possible SYN flood detected — rate: {syn_rate:.2f}/s (baseline: {baseline:.2f}/s)"
                print(f"[ALERT] {src_ip}: {alert_msg}")
                log_alert(src_ip, alert_msg)

# ---------------- BACKGROUND THREAD ----------------
def start_sniffer():
    sniff(prn=detect_syn, store=False)

sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

# ---------------- FLASK ROUTES ----------------
@app.route("/")
def show_alerts():
    alerts = []
    try:
        with open("alerts.log", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    parts = line.split(",", 2)
                    if len(parts) == 3:
                        alerts.append({
                            "timestamp": parts[0],
                            "ip": parts[1],
                            "message": parts[2]
                        })
    except FileNotFoundError:
        alerts.append({"timestamp": "-", "ip": "-", "message": "No alerts logged yet."})

    # Filter currently active IPs
    now = time.time()
    active = [ip for ip, last_seen in active_ips.items() if now - last_seen < ACTIVE_IP_TIMEOUT]

    return render_template("alerts.html", alerts=alerts, active_ips=active)

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
