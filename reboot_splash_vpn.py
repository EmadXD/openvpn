import os
import random
import time
from datetime import datetime
import pytz
import requests

# تنظیم منطقه زمانی تهران
tehran_tz = pytz.timezone("Asia/Tehran")

# لیست دامنه‌ها
domains = [
    "https://aparatvpn.com",
    "https://us.xdvpn.com",
]


def should_reboot():
    try:
        now = datetime.now(tehran_tz)
        if 4 <= now.hour < 5:
            return False
        return True
    except:
        return True


def reboot_server():
    try:
        os.system("sudo reboot")
    except:
        print("-")


def safe_get_with_retries(path, retries=5, delay=5):
    """درخواست GET با حداکثر ۵ بار تلاش با دامنه‌های تصادفی"""
    for attempt in range(1, retries + 1):
        domain = random.choice(domains)
        url = f"{domain}{path}"
        try:
            print(f"[{attempt}] Trying: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(f"[✓] Success on attempt {attempt}")
                return response
            else:
                print(f"[!] Status code {response.status_code}")
        except Exception as e:
            print(f"[!] Error on attempt {attempt}: {e}")
        time.sleep(delay)
    print("[✗] All retries failed.")
    return None


if __name__ == "__main__":
    while True:
        try:
            # نصب pip و requests در هر چرخه (پیشنهاد نمی‌شود اما طبق کد شما باقی مانده)
            os.system("sudo apt install python3-pip -y")
            time.sleep(30)
            os.system("sudo pip3 install requests")
            time.sleep(30)

            # ارسال آنلاین
            safe_get_with_retries("/XDvpn/api_v1/offline_online.php?id_key=1382&offline_online=online")

            # انتظار بین 15 تا 30 دقیقه
            time.sleep(random.randint(900, 1800))

            # ارسال آفلاین
            safe_get_with_retries("/XDvpn/api_v1/offline_online.php?id_key=1382&offline_online=offline")

            time.sleep(30)

            print("Rebooting the server...")
            reboot_server()

        except Exception as e:
            print(f"-- Exception in main loop: {e}")
