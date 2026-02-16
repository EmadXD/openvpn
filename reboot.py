import os
import random
import re
import subprocess

import requests

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


def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    return url


TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"


def create_systemd_service():
    try:
        SOCKS_PROXY = requests.get("https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php?api_key=XXX").text
        SOCKS_PROXY = clean_proxy_url(SOCKS_PROXY)
    except:
        print("[!] Could not fetch proxy, using default")
    print(f"[+] Using proxy: {SOCKS_PROXY}")

    service_content = f"""[Unit]
Description=Tun2Socks Service
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun'
ExecStartPre=/bin/bash -c 'ip addr show dev {TUN_DEV} | grep -q "{TUN_ADDR.split("/")[0]}" || ip addr add {TUN_ADDR} dev {TUN_DEV}'
ExecStartPre=/sbin/ip link set {TUN_DEV} up
ExecStart=/opt/tun2socks -device {TUN_DEV} -proxy {SOCKS_PROXY} -loglevel error
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    path = "/etc/systemd/system/tun2socks.service"
    with open(path, "w") as f:
        f.write(service_content)

    run_cmd("sudo systemctl daemon-reload")
    run_cmd("sudo systemctl enable --now tun2socks.service")
    run_cmd("sudo systemctl start tun2socks.service")
    run_cmd("sudo systemctl restart tun2socks.service")


def run_cmd(cmd):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True,
                                capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running command: {cmd}")
        if e.stderr:
            print(e.stderr.strip())


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


reboot_hour_server_min = 3
reboot_hour_server_max = 12

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
                    create_systemd_service()
                    time.sleep(5)
                    os.system("sudo pm2 restart 4")
            else:
                time.sleep(sec_wait_random)

            safe_get_with_retries(f"/XDvpn/api_v1/offline_online.php?ip={self_ip}&offline_online=offline")

            time.sleep(30)

            print("Rebooting the server...")
            reboot_server()

        except Exception as e:
            print(f"-- Exception in main loop: {e}")
