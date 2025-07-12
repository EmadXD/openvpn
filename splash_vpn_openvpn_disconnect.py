import time
from datetime import datetime
import subprocess
import os

# مسیر فایل وضعیت OpenVPN (مطمئن شو این مسیر با کانفیگ سرورت یکی باشه)
STATUS_FILE = "/etc/openvpn/logs/status.log"
# حداکثر زمان مجاز اتصال (به ثانیه)
TIMEOUT_SECONDS = 2 * 60

# ذخیره آی‌پی‌هایی که قبلاً بلاک شدن (برای جلوگیری از بلاک دوباره)
BLOCKED_IPS_FILE = "blocked_ips.txt"


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
        # بارگذاری آی‌پی‌های بلاک شده قبلی
        blocked_ips = load_blocked_ips()

        with open(STATUS_FILE, 'r') as f:
            lines = f.readlines()

        for line in lines:
            if not line.strip() or line.startswith('TITLE') or ',' not in line:
                continue

            parts = line.strip().split(',')
            if len(parts) < 4:
                continue

            _, _, real_address, connected_since = parts
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

        save_blocked_ips(blocked_ips)

    except Exception as e:
        print(f"خطا در پردازش: {e}")


while True:
    disconnect_users()
    time.sleep(120)
