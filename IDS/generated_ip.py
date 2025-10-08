# generate_alerts.py
import time
import random
import datetime

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

messages = [
    "SYN flood detected from many ports",
    "SYN scan detected",
    "SYN detected on 80/tcp",
    "SSH login failed",
    "Port scan detected",
    "ICMP ping sweep"
]

if __name__ == "__main__":
    # change interval to suit (seconds)
    interval_seconds = 1.0

    try:
        while True:
            ts = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
            ip = rand_ip()
            msg = random.choice(messages)
            line = f"{ts},{ip},{msg}\n"
            with open("alerts.log", "a") as f:
                f.write(line)
            print("wrote:", line.strip())
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("stopped")
