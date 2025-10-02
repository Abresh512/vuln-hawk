from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
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
                            "timestamp": parts[0],
                            "ip": parts[1],
                            "message": parts[2]
                        })
    except FileNotFoundError:
        alerts.append({"timestamp":"-", "ip":"-", "message":"No alerts logged yet."})

    return render_template("alerts.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
