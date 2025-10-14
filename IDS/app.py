import os
import time
import datetime
import threading
from collections import defaultdict, deque, Counter


import pyshark
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

WINDOW_SEC = 10                 
SYN_THRESHOLD = 5             
THRESHOLD_MULTIPLIER = 1     
ALERT_SUPPRESS_SECS = 30       
ACTIVE_SECONDS = 30            

ALERTS_LOG = "alerts.log"      


EFFECTIVE_THRESHOLD = SYN_THRESHOLD * THRESHOLD_MULTIPLIER


_lock = threading.Lock()
syn_packets = defaultdict(lambda: deque())  
last_alert_time = {}                        
last_seen = {}                              
packet_counts = Counter()                   


def utc_iso_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()


def get_client_ip():
    headers_to_check = [
        "CF-Connecting-IP",
        "X-Real-IP",
        "X-Forwarded-For",
        "X-Client-IP",
        "X-Forwarded",
        "Forwarded-For",
        "Forwarded"
    ]

    for header in headers_to_check:
        if header in request.headers:
            # X-Forwarded-For may contain multiple IPs
            ip = request.headers[header].split(",")[0].strip()
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip

    # Fallback to Flask's get_client_ip
    if request.get_client_ip:
        return request.get_client_ip

    # If Brave hides IP completely, fallback to loopback
    return "127.0.0.1"

def log_alert_line(ts_iso, ip, message):
    line = f"{ts_iso}, {ip}, {message}\n"
    try:

        #Append an alert line to ALERTS_LOG (CSV style).
        with open(ALERTS_LOG, "a") as f:
            f.write(line)
    except Exception as e:
        print("[ERROR] writing alert log:", e)

# ----------  capture & detect ----------
def capture_packets(interface=None):
  
    display_filter = "tcp.flags.syn == 1 && tcp.flags.ack == 0"
    iface = interface or os.environ.get("IFACE", None)
    print(f"[+] Starting pyshark LiveCapture on iface: {iface or 'default'} (filter: {display_filter})")
    try:
        capture = pyshark.LiveCapture(interface=iface, display_filter=display_filter, use_json=True)
        # sniff_continuously yields parsed packets as they arrive
        for pkt in capture.sniff_continuously():
            try:
                # Some packets may not have IP layer depending on capture; guard access
                if not hasattr(pkt, "ip"):
                    continue
                src = pkt.ip.src
                dst = pkt.ip.dst
                sport = pkt.tcp.srcport if hasattr(pkt, "tcp") else "?"
                dport = pkt.tcp.dstport if hasattr(pkt, "tcp") else "?"
                now = time.time()

                # update last seen and counts for both src and dst
                with _lock:
                    last_seen[src] = now
                    last_seen[dst] = now
                    packet_counts[src] += 1
                    packet_counts[dst] += 1

                    # record SYN timestamp for src
                    dq = syn_packets[src]
                    dq.append(now)
                    # drop old timestamps outside sliding window
                    while dq and (now - dq[0]) > WINDOW_SEC:
                        dq.popleft()

                    syn_count = len(dq)
                    if syn_count > EFFECTIVE_THRESHOLD:
                        last = last_alert_time.get(src, 0)
                        if (now - last) > ALERT_SUPPRESS_SECS:
                            ts_iso = utc_iso_now()
                            msg = f"SYN flood suspected from port {sport} to {dst} ({syn_count} SYNs in {WINDOW_SEC}s)"
                            log_alert_line(ts_iso, src, msg)
                            last_alert_time[src] = now
                            print(f"[ALERT] {src} -> {dst}: {msg}")

            except Exception as inner_e:
                print("[ERROR] packet processing:", inner_e)
    except Exception as e:
        print("[ERROR] capture_packets:", e)
        print("Make sure tshark is installed and you have permission to capture on the interface.")
        raise

def start_capture_thread(iface=None):

    t = threading.Thread(target=capture_packets, kwargs={"interface": iface}, daemon=True)
    t.start()
    return t


def parse_alerts_file(path=ALERTS_LOG):

    alerts = []
    syn_counter = Counter()
    if not os.path.exists(path):
        return alerts, syn_counter

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 2)
                if len(parts) != 3:
                    continue
                timestamp = parts[0].strip()
                ip = parts[1].strip()
                message = parts[2].strip()
                lower_msg = message.lower()
                # basic heuristic to mark SYN-related alerts
                is_syn = "syn" in lower_msg or "syn flood" in lower_msg or "tcp:flags=syn" in lower_msg
                alerts.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "message": message,
                    "is_syn": is_syn
                })
                if is_syn:
                    syn_counter[ip] += 1
    except Exception as e:
        print("[ERROR] parse_alerts_file:", e)

    alerts.reverse()  # most recent first
    return alerts, syn_counter


def get_active_ips(window=ACTIVE_SECONDS, top_n=50):
   
    now = time.time()
    items = []
    with _lock:
        for ip, ts in last_seen.items():
            age = now - ts
            if age <= window:
                iso = datetime.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat()
                cnt = packet_counts.get(ip, 0)
                items.append((ip, iso, int(age), cnt))
    # sort by most recent (ascending)
    items.sort(key=lambda x: x[2])
    return items[:top_n]

@app.route("/")
def show_alerts():
    alerts, syn_counter = parse_alerts_file()
    top_offenders = syn_counter.most_common(10)
    active = get_active_ips()
    return render_template("alerts.html", alerts=alerts, top_offenders=top_offenders, active_ips=active)

@app.route("/alerts.json")
def alerts_json():
    alerts, _ = parse_alerts_file()
    return jsonify(alerts)

@app.route("/active.json")
def active_json():
    active = get_active_ips()
    out = [{"ip": ip, "last_seen": last_seen_iso, "age_s": age, "count": count}
           for ip, last_seen_iso, age, count in active]
    return jsonify(out)

if __name__ == "__main__":
    iface = os.environ.get("IFACE", None)
    print("Starting capture thread on iface:", iface or "default (pyshark chooses)")
    start_capture_thread(iface=iface)
    app.run(debug=True, host="0.0.0.0", port=5000)
