#!/usr/bin/env python3
import os
import re
import subprocess
import sys

import time

# ---------------- تنظیمات ----------------
IPSET_NAME = "proxylist"
VPN_SUBNET = "10.8.0.0/20"
PROXY_TABLE = "100"  # شماره routing table برای پروکسی


def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    return url


DOMAINS = [
    "browserleaks.com",
    "1e100.net",
    "2mdn-cn.net",
    "2mdn.net",
    "accounts.google.com",
    "ad.doubleclick.net",
    "admob-api.google.com",
    "admob-cn.com",
    "admob.com",
    "admob.google.com",
    "admob.googleapis.com",
    "ads.youtube.com",
    "adservice.google.com",
    "adservices.google.com",
    "analytics.google.com",
    "app-measurement-cn.com",
    "app-measurement.com",
    "apps.admob.com",
    "clients.google.com",
    "developers.google.com",
    "doubleclick-cn.net",
    "doubleclick.net",
    "firebasedynamiclinks.googleapis.com",
    "firebase.google.com",
    "firebaseinstallations.googleapis.com",
    "firebaseremoteconfig.googleapis.com",
    "g.doubleclick.net",
    "google-analytics-cn.com",
    "google-analytics.com",
    "google.com",
    "googleadservices.com",
    "googleads.g.doubleclick.net",
    "googleapis.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "gstatic.com",
    "pagead.l.doubleclick.net",
    "pagead2.googlesyndication.com",
    "play.google.com",
    "play.googleapis.com",
    "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "support.google.com",
    "tpc.googlesyndication.com",
]

GOOGLE_RANGES = [
    '40.160.248.145/32',
    '57.140.192.0/18', '64.15.112.0/20', '64.233.160.0/19', '66.22.228.0/23',
    '66.102.0.0/20', '66.249.64.0/19', '70.32.128.0/19', '72.14.192.0/18',
    '74.114.24.0/21', '74.125.0.0/16', '104.237.160.0/19', '107.178.192.0/18',
    '108.170.192.0/18', '108.177.0.0/17', '136.22.160.0/20', '136.22.176.0/21',
    '136.22.184.0/23', '136.22.186.0/24', '136.124.0.0/15', '142.250.0.0/15',
    '152.65.208.0/22', '152.65.214.0/23', '152.65.218.0/23', '152.65.222.0/23',
    '152.65.224.0/19', '162.120.128.0/17', '162.216.148.0/22', '172.110.32.0/21',
    '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16', '173.255.112.0/20',
    '192.104.160.0/23', '192.178.0.0/15', '193.186.4.0/24', '199.36.154.0/23',
    '199.36.156.0/24', '207.223.160.0/20', '208.65.152.0/22', '208.68.108.0/22',
    '208.81.188.0/22', '208.117.224.0/19', '209.85.128.0/17', '216.58.192.0/19',
    '216.73.80.0/20', '216.239.32.0/19', '216.252.220.0/22'
]

TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"


# ---------------- توابع کمکی ----------------
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


# ---------------- نصب بسته‌ها ----------------
def setup_install_packages():
    print("[+] Installing required packages and building tun2socks...")

    run_cmd("sudo apt update")
    run_cmd("sudo apt install -y wget git make ipset build-essential")
    run_cmd("sudo apt install -y shadowsocks-libev")

    run_cmd("sudo apt-get install python3-pip -y")
    run_cmd("sudo pip3 install requests")

    # نصب Go
    run_cmd("sudo wget https://go.dev/dl/go1.23.1.linux-amd64.tar.gz -O /tmp/go1.23.1.linux-amd64.tar.gz")
    run_cmd("sudo rm -rf /usr/local/go")
    run_cmd("sudo tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz")

    # اضافه کردن Go به PATH فقط برای فرایندهای بعدی
    go_path = "/usr/local/go/bin"
    os.environ["PATH"] = go_path + ":" + os.environ["PATH"]

    # کلون و ساخت tun2socks
    run_cmd("sudo rm -rf tun2socks")
    run_cmd("sudo git clone https://github.com/xjasonlyu/tun2socks.git")
    os.chdir("tun2socks")
    run_cmd("make tun2socks")
    run_cmd("sudo cp ./build/tun2socks /usr/local/bin")
    os.chdir("..")
    print("[+] Installation completed successfully.")


# ---------------- ipset ----------------
def setup_ipset():
    run_cmd(f"sudo ipset destroy {IPSET_NAME} || true")
    run_cmd(f"sudo ipset create {IPSET_NAME} hash:net || true")


def add_google_ranges_to_ipset():
    print("[+] Adding Google IP ranges...")
    for range_cidr in GOOGLE_RANGES:
        run_cmd(f"sudo ipset add {IPSET_NAME} {range_cidr} -exist")


def update_ipset():
    for domain in DOMAINS:
        print(f"[+] Resolving {domain}...")
        try:
            result = subprocess.run(f"dig +short {domain}", shell=True,
                                    check=True, capture_output=True, text=True)
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for ip in ips:
                run_cmd(f"sudo ipset add {IPSET_NAME} {ip} -exist")
            if ips:
                print(f"[+] {len(ips)} IPs added for {domain}")
        except Exception as e:
            print(f"[!] Error resolving {domain}: {e}")


# ---------------- tun2socks ----------------
def setup_tun2socks_interface():
    run_cmd(f"sudo ip tuntap add dev {TUN_DEV} mode tun || true")
    run_cmd(f"sudo ip addr add {TUN_ADDR} dev {TUN_DEV} || true")
    run_cmd(f"sudo ip link set {TUN_DEV} up")


def setup_vpn_forwarding():
    run_cmd(f"sudo iptables -A FORWARD -s {VPN_SUBNET} -o {TUN_DEV} -j ACCEPT")
    run_cmd(f"sudo iptables -A FORWARD -d {VPN_SUBNET} -i {TUN_DEV} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run_cmd(f"sudo iptables -t nat -A POSTROUTING -o {TUN_DEV} -s {VPN_SUBNET} -j MASQUERADE")


def setup_iptables_fwmark():
    run_cmd("sudo iptables -t mangle -F PREROUTING")
    run_cmd(
        f"sudo iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")


def setup_tun2socks_routing():
    run_cmd(
        f"grep -q '^{PROXY_TABLE} tun2socks' /etc/iproute2/rt_tables || echo '{PROXY_TABLE} tun2socks' | sudo tee -a /etc/iproute2/rt_tables")
    run_cmd("sudo ip rule del fwmark 1 table tun2socks || true")
    run_cmd("sudo ip route flush table tun2socks || true")
    run_cmd("sudo ip rule add fwmark 1 table tun2socks")
    run_cmd(f"sudo ip route add default via 192.168.255.1 dev {TUN_DEV} table tun2socks")


# ---------------- kernel optimizations ----------------
def apply_kernel_optimizations():
    sysctl_settings = {
        "net.ipv4.ip_forward": "1",
        "net.core.rmem_max": "26214400",
        "net.core.wmem_max": "26214400",
        "net.core.somaxconn": "4096",
        "net.ipv4.tcp_max_syn_backlog": "4096",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.tcp_tw_reuse": "1",
    }
    for key, value in sysctl_settings.items():
        run_cmd(f"sudo sysctl -w {key}={value}")


# ---------------- systemd service ----------------
def create_systemd_service():
    try:
        import requests
        SOCKS_PROXY = requests.get("https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php").text
        SOCKS_PROXY = clean_proxy_url(SOCKS_PROXY)
    except:
        print("---")
    print(SOCKS_PROXY)

    service_content = f"""[Unit]
Description=Tun2Socks Service
After=network.target

[Service]
ExecStart=/usr/local/bin/tun2socks -device {TUN_DEV} -proxy {SOCKS_PROXY} -loglevel error
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


# ---------------- main ----------------
def main():
    if os.geteuid() != 0:
        print("[!] لطفاً اسکریپت را با sudo اجرا کنید")
        sys.exit(1)

    setup_install_packages()
    setup_ipset()
    add_google_ranges_to_ipset()
    update_ipset()
    setup_tun2socks_interface()
    setup_vpn_forwarding()
    setup_iptables_fwmark()
    setup_tun2socks_routing()
    apply_kernel_optimizations()
    create_systemd_service()

    print("\n[+] آماده شد!")
    print("اکنون ترافیک دامنه‌ها و رنج‌های Google از طریق tun2socks عبور می‌کند.")


if __name__ == "__main__":
    try:
        main()
        time.sleep(90000000)
    except KeyboardInterrupt:
        time.sleep(90000000)
        print("خروج کاربر...")
    except Exception as e:
        time.sleep(90000000)
        print(f"خطا: {e}")
