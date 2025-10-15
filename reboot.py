import os
import random
import subprocess
import time

domains = [
    "https://aparatvpn.com",
    "https://us.xdvpn.com",
]

restart_pm2_tun2socks = True


def reboot_server():
    try:
        os.system("sudo reboot")
    except:
        print("-")


def safe_get_with_retries(path, retries=5, delay=5):
    for attempt in range(1, retries + 1):
        domain = random.choice(domains)
        url = f"{domain}{path}"
        try:
            print(f"[{attempt}] Trying: {url}")
            import requests
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


def get_main_ip():
    try:
        result = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True)
        ip = result.decode().strip()
        return ip
    except Exception as e:
        print(f"Error getting IP: {e}")
        return None


reboot_hour_server_min = 100
reboot_hour_server_max = 200

restart_script_minutes_server_min = 10
restart_script_minutes_server_max = 15

if __name__ == "__main__":
    while True:
        try:
            os.system("sudo apt install python3-pip -y")
            time.sleep(30)
            os.system("sudo pip3 install requests")
            time.sleep(30)
            self_ip = get_main_ip()

            safe_get_with_retries(f"/XDvpn/api_v1/offline_online.php?ip={self_ip}&offline_online=online")

            sec_wait_random = random.randint(int(reboot_hour_server_min * 3600), int(reboot_hour_server_max * 3600))
            if restart_pm2_tun2socks:
                sec_wait_restart = random.randint(int(restart_script_minutes_server_min * 60),
                                                  int(restart_script_minutes_server_max * 60))
                for i in range(int(sec_wait_random / sec_wait_restart)):  # ---7000/500 = 14 count for
                    time.sleep(sec_wait_restart)
                    os.system("sudo systemctl restart tun2socks")
                    time.sleep(10)
                    os.system("sudo pm2 restart 4")
            else:
                time.sleep(sec_wait_random)

            safe_get_with_retries(f"/XDvpn/api_v1/offline_online.php?ip={self_ip}&offline_online=offline")

            time.sleep(30)

            print("Rebooting the server...")
            reboot_server()

        except Exception as e:
            print(f"-- Exception in main loop: {e}")
