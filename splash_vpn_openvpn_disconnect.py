import re
import time
from datetime import datetime
import subprocess
import os

STATUS_FILE = "/var/log/openvpn/status.log"
TIMEOUT_SECONDS = 2 * 60  # 2 دقیقه
BLOCKED_IPS_FILE = "blocked_ips.txt"

if os.path.exists(BLOCKED_IPS_FILE):
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


def parse_status_file():
    client_list = []
    routing_table = {}

    with open(STATUS_FILE, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        if line.startswith("client"):
            parts = line.split(',')
            if len(parts) >= 5:
                common_name = parts[0]
                real_address = parts[1]
                connected_since = parts[4]
                client_list.append({
                    "real_address": real_address,
                    "connected_since": connected_since
                })

        if line.startswith("10."):
            parts = line.split(',')
            if len(parts) >= 3:
                virtual_address = parts[0]
                real_address = parts[2]
                routing_table[real_address] = virtual_address

    return client_list, routing_table


def disconnect_users():
    try:
        blocked_ips = load_blocked_ips()
        client_list, routing_table = parse_status_file()
        print(client_list, routing_table)

        current_time = datetime.now()

        for client in client_list:
            real_address = client["real_address"]
            connected_since = client["connected_since"]

            virtual_address = routing_table.get(real_address)
            if not virtual_address or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", virtual_address):
                continue

            try:
                connected_time = datetime.strptime(connected_since, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

            duration = (current_time - connected_time).total_seconds()

            if duration > TIMEOUT_SECONDS and virtual_address not in blocked_ips:
                print(f"قطع اتصال کاربر با IP اختصاص‌یافته {virtual_address} (مدت اتصال: {int(duration)} ثانیه)")

                subprocess.run(['sudo', 'iptables', '-I', 'FORWARD', '1', '-d', virtual_address, '-j', 'DROP'])
                blocked_ips.add(virtual_address)
                print(f"ترافیک به IP {virtual_address} قطع شد.")

        try:
            save_blocked_ips(blocked_ips)
        except Exception as e:
            print(f"خطا در ذخیره فایل blocked_ips: {e}")

    except Exception as e:
        print(f"خطا در پردازش: {e}")


while True:
    try:
        disconnect_users()
        time.sleep(60)
    except Exception as e:
        print(f"خطا در لوپ اصلی: {e}")
