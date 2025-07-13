import os
import time
from datetime import datetime
import pytz

# تنظیم منطقه زمانی تهران
tehran_tz = pytz.timezone("Asia/Tehran")


def should_reboot():
    # دریافت زمان فعلی به وقت تهران
    try:
        now = datetime.now(tehran_tz)
        # بررسی بازه زمانی بین 4 صبح تا 6 صبح
        if now.hour >= 4 and now.hour < 5:
            return False
        return True
    except:
        return True


def reboot_server():
    # اجرای دستور ریبوت
    try:
        os.system("sudo reboot")
    except:
        print("-")


if __name__ == "__main__":
    while True:
        try:
            time.sleep(1000)
            if should_reboot():
                print("Rebooting the server...")
                reboot_server()
            else:
                print("Skipping reboot during restricted hours (4 AM to 6 AM Tehran time).")
        except:
            print("--")
        # صبر کردن برای یک ساعت (3600 ثانیه)
