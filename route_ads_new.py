#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import time

import requests

# ---------------- تنظیمات ----------------
IPSET_NAME = "proxylist"
VPN_SUBNET = "10.8.0.0/20"
PROXY_TABLE = "100"  # شماره routing table برای پروکسی

TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"

# ---------------- utility ----------------
def run_cmd(cmd, check=False, capture=False):
    print(f"[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True,
                            check=check, capture_output=capture, text=True)
    if capture and result.stdout:
        return result.stdout.strip()
    return None

def run_cmd_safe(cmd):
    try:
        return run_cmd(cmd, check=True, capture=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {cmd}\n    stderr: {e.stderr.strip() if e.stderr else '---'}")
        return None

def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    return url

# ---------------- setup/install ----------------
def setup_install_packages():
    tun2socks_installed = os.path.exists("/usr/local/bin/tun2socks") or \
        subprocess.run("which tun2socks", shell=True, capture_output=True).returncode == 0

    if tun2socks_installed:
        print("[+] tun2socks قبلاً نصب شده است، از مرحله نصب عبور می‌کنیم.")
        return

    print("[+] Installing required packages and building tun2socks...")
    run_cmd("sudo apt update")
    run_cmd("sudo apt install -y wget git make ipset build-essential shadowsocks-libev python3-pip")
    run_cmd("sudo pip3 install requests")

    # نصب Go
    run_cmd("sudo wget https://go.dev/dl/go1.23.1.linux-amd64.tar.gz -O /tmp/go1.23.1.linux-amd64.tar.gz")
    run_cmd("sudo rm -rf /usr/local/go")
    run_cmd("sudo tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz")
    os.environ["PATH"] = "/usr/local/go/bin:" + os.environ.get("PATH", "")

    # clone & build
    run_cmd("sudo rm -rf tun2socks")
    run_cmd("sudo git clone https://github.com/xjasonlyu/tun2socks.git")
    os.chdir("tun2socks")
    run_cmd("make tun2socks")
    run_cmd("sudo cp ./build/tun2socks /usr/local/bin")
    os.chdir("..")
    print("[+] Installation completed successfully.")

# ---------------- ipset ----------------
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
    "securepubads.google.com",
    "support.google.com",
    "tpc.googlesyndication.com",
]

def setup_ipset():
    run_cmd(f"sudo ipset destroy {IPSET_NAME} || true")
    run_cmd(f"sudo ipset create {IPSET_NAME} hash:net || true")

def add_google_ranges_to_ipset():
    try:
        GOOGLE_RANGES = requests.get(
            "https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/google_ip_list.json", timeout=10).json()
    except Exception as e:
        print(f"[!] Couldn't fetch GOOGLE_RANGES: {e}")
        GOOGLE_RANGES = []
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

# ---------------- tun2socks interface ----------------
def ensure_tun_dev_up(dev=TUN_DEV, addr=TUN_ADDR, retries=5, wait=1):
    """
    Ensure the TUN device exists, has the address and is UP.
    Retries a few times to handle races.
    """
    # try to remove stale device then create fresh one
    run_cmd(f"sudo ip tuntap del dev {dev} mode tun || true")
    run_cmd(f"sudo ip tuntap add dev {dev} mode tun || true")
    run_cmd(f"sudo ip addr add {addr} dev {dev} || true")
    run_cmd(f"sudo ip link set {dev} up || true")

    for i in range(retries):
        out = run_cmd_safe(f"ip link show {dev}")
        if out and "state UP" in out:
            print(f"[+] {dev} is up")
            return True
        print(f"[!] {dev} not up yet, retry {i+1}/{retries}")
        time.sleep(wait)
        # attempt again
        run_cmd(f"sudo ip link set {dev} up || true")
    print(f"[!] Failed to bring {dev} up after {retries} retries")
    return False

def setup_tun2socks_interface():
    print("[+] Setting up TUN interface")
    ok = ensure_tun_dev_up()
    if not ok:
        print("[!] Warning: couldn't ensure TUN interface is up. Continuing but service may not receive traffic.")

# ---------------- iptables & routing ----------------
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
    # fetch socks proxy if available
    try:
        SOCKS_PROXY_RAW = requests.get("https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php", timeout=5).text
        socks = clean_proxy_url(SOCKS_PROXY_RAW)
    except Exception as e:
        print(f"[!] Could not fetch proxy from API: {e}")
        socks = SOCKS_PROXY

    print(f"[+] Using proxy: {socks}")

    service_content = f"""[Unit]
Description=Tun2Socks Service
After=network.target

[Service]
# Ensure TUN exists & is up before starting (helps avoid 'device is not up' race)
ExecStartPre=/sbin/ip tuntap del dev {TUN_DEV} mode tun || true
ExecStartPre=/sbin/ip tuntap add dev {TUN_DEV} mode tun || true
ExecStartPre=/sbin/ip addr add {TUN_ADDR} dev {TUN_DEV} || true
ExecStartPre=/sbin/ip link set {TUN_DEV} up || true

ExecStart=/usr/local/bin/tun2socks -device {TUN_DEV} -proxy {socks} -loglevel error
Restart=always
RestartSec=3
StartLimitIntervalSec=0
LimitNOFILE=65536

StandardOutput=append:/var/log/tun2socks.log
StandardError=append:/var/log/tun2socks.log

[Install]
WantedBy=multi-user.target
"""
    path = "/etc/systemd/system/tun2socks.service"
    with open(path, "w") as f:
        f.write(service_content)
    run_cmd("sudo systemctl daemon-reload")
    run_cmd("sudo systemctl enable tun2socks.service")
    run_cmd("sudo systemctl restart tun2socks.service")
    time.sleep(1)

    # verify device up; if not, try to set it and restart once
    out = run_cmd_safe(f"ip link show {TUN_DEV}")
    if not out or "state UP" not in out:
        print("[!] After service start, device not UP — attempting to bring up & restart service")
        run_cmd(f"sudo ip link set {TUN_DEV} up || true")
        run_cmd("sudo systemctl restart tun2socks.service")
        time.sleep(1)
    print("[+] Systemd service created and started (check /var/log/tun2socks.log for details)")

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
    except KeyboardInterrupt:
        print("خروج کاربر...")
    except Exception as e:
        print(f"خطا: {e}")
