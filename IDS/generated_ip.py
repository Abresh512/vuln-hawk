#!/usr/bin/env python3
# simulate_alerts.py
# Runs in a loop and appends synthetic alerts to alerts.log for dashboard testing.

import time
import random
from datetime import datetime
import argparse
import os
import signal
import sys

DEFAULT_LOG = "alerts.log"

SAMPLE_MESSAGES = [
    "SYN flood detected (high rate of SYN packets)",
    "Suspicious SYN scan (multiple SYNs, no handshake)",
    "High connection attempt rate",
    "Possible TCP SYN stealth scan",
    "Repeated SYNs from single source"
]

def make_alert_line(ip, msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    # Customize the format to whatever your dashboard expects
    return f"{ts} | {ip} | {msg}\n"

def random_ip():
    # generate randomized but realistic internal/testable IPs; avoid real public IPs if you want
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def run(logfile, rate_per_minute):
    interval = 60.0 / max(1, rate_per_minute)
    print(f"Appending simulated alerts to {logfile} at ~{rate_per_minute} alerts/min (interval {interval:.2f}s). Ctrl-C to stop.")
    try:
        while True:
            ip = random_ip()
            msg = random.choice(SAMPLE_MESSAGES)
            line = make_alert_line(ip, msg)
            with open(logfile, "a") as f:
                f.write(line)
            # optionally print to console for debugging
            print(line.strip())
            time.sleep(interval * random.uniform(0.6, 1.4))  # small jitter
    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate IDS alerts by appending to a log file.")
    parser.add_argument("--log", "-l", default=DEFAULT_LOG, help="Path to alerts.log used by your dashboard")
    parser.add_argument("--rate", "-r", type=int, default=20, help="Approx alerts per minute")
    args = parser.parse_args()
    run(args.log, args.rate)
