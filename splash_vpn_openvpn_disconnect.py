import time
from datetime import datetime
import subprocess
import os

STATUS_FILE = "/var/log/openvpn/status.log"
TIMEOUT_SECONDS = 2 * 60
BLOCKED_IPS_FILE = "blocked_ips.txt"

open(BLOCKED_IPS_FILE, "w").close()


def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return set(ip.strip() for ip in f.readlines())
    return set()


def save_blocked_ips(ips):
    with open(BLOCKED_IPS_FILE, "w") as f:
        for ip in ips:
            f.write(ip + "\n")


def disconnect_users():
    try:
        try:
            blocked_ips = load_blocked_ips()
        except:
            blocked_ips = set()

        with open(STATUS_FILE, 'r') as f:
            lines = f.readlines()

        for line in lines:
            if not line.strip() or line.startswith('TITLE') or ',' not in line:
                continue

            parts = line.strip().split(',')

            if len(parts) < 4:
                continue

            real_address = parts[0]
            connected_since = parts[3]

            try:
                connected_time = datetime.strptime(connected_since, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

            current_time = datetime.now()
            duration = (current_time - connected_time).total_seconds()

            ip_only = real_address.split(':')[0]

            if duration > TIMEOUT_SECONDS and ip_only not in blocked_ips:
                print(f"قطع اتصال کاربر {ip_only} (مدت اتصال: {int(duration)} ثانیه)")

                subprocess.run(['sudo', 'iptables', '-I', 'FORWARD', '1', '-d', ip_only, '-j', 'DROP'])
                blocked_ips.add(ip_only)
                print(f"ترافیک به IP {ip_only} قطع شد.")

        try:
            save_blocked_ips(blocked_ips)
        except:
            print("-")

    except Exception as e:
        print(f"خطا در پردازش: {e}")


while True:
    try:
        disconnect_users()
        time.sleep(60)
    except:
        print("-")
