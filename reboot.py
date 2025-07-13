import os
import time
from datetime import datetime
import pytz

# تنظیم منطقه زمانی تهران
tehran_tz = pytz.timezone("Asia/Tehran")


def should_reboot():
    # دریافت زمان فعلی به وقت تهران
    now = datetime.now(tehran_tz)
    # بررسی بازه زمانی بین 4 صبح تا 6 صبح
    if now.hour >= 4 and now.hour < 5:
        return False
    return True


def reboot_server():
    # اجرای دستور ریبوت
    os.system("sudo reboot")


if __name__ == "__main__":
    while True:
        time.sleep(3600)
        if should_reboot():
            print("Rebooting the server...")
            reboot_server()
        else:
            print("Skipping reboot during restricted hours (4 AM to 6 AM Tehran time).")
        # صبر کردن برای یک ساعت (3600 ثانیه)
