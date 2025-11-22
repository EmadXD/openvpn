#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import requests
import time

use_binary_created = True
full_route_to_proxy = False  # ---if True only use port 80,443
# ---------------- تنظیمات ----------------
IPSET_NAME = "proxylist"
VPN_SUBNET = "10.8.0.0/14"
PROXY_TABLE = "100"  # شماره routing table برای پروکسی
TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"

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
DOMAINS.extend([
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
])

GOOGLE_RANGES = requests.get(
    "https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/google_ip_list.json").json()


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


def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    return url


# ---------------- نصب بسته‌ها ----------------
def setup_install_packages():
    tun2socks_installed = os.path.exists("/usr/local/bin/tun2socks") or \
                          subprocess.run("which tun2socks", shell=True, capture_output=True).returncode == 0

    if tun2socks_installed:
        print("[+] tun2socks قبلاً نصب شده است، از مرحله نصب عبور می‌کنیم.")
        return

    print("[+] Installing required packages and building tun2socks...")
    run_cmd("apt update")
    run_cmd("apt install -y wget git make ipset build-essential shadowsocks-libev python3-pip")
    run_cmd("pip3 install requests")

    # نصب Go
    run_cmd("wget https://aparatvpn.com/go1.23.1.linux-amd64.tar.gz -O /tmp/go1.23.1.linux-amd64.tar.gz")
    run_cmd("rm -rf /usr/local/go")
    run_cmd("tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz")
    os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]

    # ساخت tun2socks
    run_cmd("rm -rf tun2socks")
    if use_binary_created:
        run_cmd("sudo rm -rf /usr/local/bin/tun2socks")
        run_cmd("sudo wget https://aparatvpn.com/tun2socks -O /usr/local/bin/tun2socks")
        run_cmd("sudo chmod 777 /usr/local/bin/tun2socks")
    else:
        run_cmd("git clone https://github.com/xjasonlyu/tun2socks.git")
        os.chdir("tun2socks")
        run_cmd("make tun2socks")
        run_cmd("cp ./build/tun2socks /usr/local/bin")

    os.chdir("..")
    print("[+] Installation completed successfully.")


# ---------------- ipset ----------------
def setup_ipset():
    run_cmd(f"ipset destroy {IPSET_NAME} || true")
    run_cmd(f"ipset create {IPSET_NAME} hash:net || true")


def add_google_ranges_to_ipset():
    print("[+] Adding Google IP ranges...")
    for range_cidr in GOOGLE_RANGES:
        run_cmd(f"ipset add {IPSET_NAME} {range_cidr} -exist")


def update_ipset():
    for domain in DOMAINS:
        print(f"[+] Resolving {domain}...")
        try:
            result = subprocess.run(f"dig +short {domain}", shell=True,
                                    check=True, capture_output=True, text=True)
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for ip in ips:
                run_cmd(f"ipset add {IPSET_NAME} {ip} -exist")
            if ips:
                print(f"[+] {len(ips)} IPs added for {domain}")
        except Exception as e:
            print(f"[!] Error resolving {domain}: {e}")


# ---------------- tun2socks ----------------
def setup_tun2socks_interface():
    # اگر interface موجود نیست بساز
    run_cmd(f"ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun")
    # اگر IP اضافه نشده است، اضافه کن
    run_cmd(f"ip addr show dev {TUN_DEV} | grep -q '{TUN_ADDR.split('/')[0]}' || ip addr add {TUN_ADDR} dev {TUN_DEV}")
    # مطمئن شو interface up است
    run_cmd(f"ip link set {TUN_DEV} up")


def setup_vpn_forwarding():
    run_cmd(f"iptables -A FORWARD -s {VPN_SUBNET} -o {TUN_DEV} -j ACCEPT")
    run_cmd(f"iptables -A FORWARD -d {VPN_SUBNET} -i {TUN_DEV} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run_cmd(f"iptables -t nat -A POSTROUTING -o {TUN_DEV} -s {VPN_SUBNET} -j MASQUERADE")


def setup_iptables_fwmark():
    run_cmd("iptables -t mangle -F PREROUTING")
    if full_route_to_proxy:
        run_cmd(
            f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")
    else:
        run_cmd(
            f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -p tcp -m multiport --dports 80,443,8080,8443 -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")


def setup_tun2socks_routing():
    run_cmd(
        f"grep -q '^{PROXY_TABLE} tun2socks' /etc/iproute2/rt_tables || echo '{PROXY_TABLE} tun2socks' >> /etc/iproute2/rt_tables")
    run_cmd("ip rule del fwmark 1 table tun2socks || true")
    run_cmd("ip route flush table tun2socks || true")
    run_cmd("ip rule add fwmark 1 table tun2socks")
    run_cmd(f"ip route add default via {TUN_ADDR.split('/')[0]} dev {TUN_DEV} table tun2socks")


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
        run_cmd(f"sysctl -w {key}={value}")


# ---------------- systemd service ----------------
def create_systemd_service():
    try:
        SOCKS_PROXY = requests.get("https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php").text
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

    # کوتاه صبر کن تا network stack آماده شود
    time.sleep(15)

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

    print("\n[+] آماده شد! ترافیک Google و دامنه‌ها از طریق tun2socks عبور می‌کند.")


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
