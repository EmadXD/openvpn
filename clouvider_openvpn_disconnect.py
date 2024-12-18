import json
import subprocess
import time
from datetime import datetime


def disconnect_users():
    # دریافت داده‌های JSON از دستور VPNStatus
    vpn_status_command = ['sudo', '/usr/local/openvpn_as/scripts/sacli', '--pf', 'json', 'VPNStatus']
    result = subprocess.run(vpn_status_command, capture_output=True, text=True)

    # اگر خروجی موفق بود، داده‌های JSON را پردازش کن
    if result.returncode == 0:
        vpn_data = json.loads(result.stdout)

        # زمان کنونی به ثانیه (time_t)
        current_time = int(datetime.now().timestamp())

        # مدت زمان مجاز (۲ دقیقه) به ثانیه
        timeout_threshold = 2 * 60  # ۲ دقیقه به ثانیه

        # یک لیست برای ذخیره آدرس‌های IP که باید مسدود شوند
        blocked_ips = []

        # پیمایش تمام بخش‌های openvpn_x
        for key in vpn_data:
            if key.startswith('openvpn_'):  # فقط بخش‌های openvpn_x را پردازش می‌کنیم
                print(f"بررسی کاربران در {key}...")
                # بررسی کاربران متصل به این بخش
                for client in vpn_data[key]['client_list']:
                    # زمان اتصال در فرمت "YYYY-MM-DD HH:MM:SS"
                    connection_time_str = client[6]
                    connection_time = int(datetime.strptime(connection_time_str, '%Y-%m-%d %H:%M:%S').timestamp())

                    # محاسبه مدت زمان اتصال
                    connection_duration = current_time - connection_time

                    # اگر زمان اتصال بیشتر از ۲ دقیقه باشد
                    if connection_duration > timeout_threshold:
                        real_address = client[2]  # آدرس واقعی کاربر (آدرس IP و پورت)
                        # print(f"قطع اتصال کاربر {real_address} که بیش از ۲ دقیقه است متصل است.")

                        # استخراج آدرس IP از رشته (برای مثال "46.246.98.88:55960" -> "46.246.98.88")
                        ip_address = real_address.split(":")[0].strip()  # حذف فضای اضافی

                        # اضافه کردن آدرس IP به لیست مسدود شده
                        if ip_address not in blocked_ips:
                            blocked_ips.append(ip_address)

        # اگر لیستی از آدرس‌های IP مسدود شده وجود داشته باشد
        if blocked_ips:
            # اجرای دستور iptables برای مسدود کردن تمام آدرس‌ها به صورت یکجا
            # حذف فضای اضافی بین آدرس‌های IP

            iptables_command = ['sudo', 'iptables', '-I', 'FORWARD', '1', '-d', ','.join(blocked_ips), '-j', 'DROP']

            subprocess.run(iptables_command)
            print(f"ترافیک به تعداد آدرس‌های IP مسدود شد: {len(blocked_ips)}")
    else:
        print("خطا در دریافت داده‌های OpenVPN.")


while True:
    disconnect_users()
    time.sleep(60)
