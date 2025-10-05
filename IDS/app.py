from flask import Flask, render_template, jsonify
import os

app = Flask(__name__)


def parse_alerts_file(path="alerts.log"):
    alerts = []
    if not os.path.exists(path):
        return alerts

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # expected format: timestamp,ip,message
            parts = line.split(",", 2)
            if len(parts) != 3:
                # skip malformed lines
                continue
            timestamp, ip, message = parts[0].strip(), parts[1].strip(), parts[2].strip()
            is_syn = any(k in message.lower() for k in ("syn", "syn flood", "syn detected", "syn scan"))
            alerts.append({
                "timestamp": timestamp,
                "ip": ip,
                "message": message,
                "is_syn": is_syn
            })

    # newest first
    alerts.reverse()
    return alerts


@app.route("/")
def show_alerts():
    alerts = parse_alerts_file()
    # if no alerts, show friendly message in template
    return render_template("alerts.html", alerts=alerts)


@app.route("/alerts.json")
def alerts_json():
    alerts = parse_alerts_file()
    return jsonify(alerts)


if __name__ == "__main__":
    # debug only for development
    app.run(debug=True, host="0.0.0.0", port=5000)
