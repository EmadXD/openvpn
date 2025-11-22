#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import time
import requests

use_binary_created = True

# ---------------- تنظیمات ----------------
VPN_SUBNET = "10.8.0.0/14"
TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"
PROXY_TABLE = "100"  # شماره routing table

DOMAINS = [
    "1e100.net",
    "1e100.com",
    "1e100.org",
    "2mdn-cn.net",
    "2mdn.net",
    "ad.doubleclick.net",
    "adclick.g.doubleclick.net",
    "admob-api.google.com",
    "admob-cn.com",
    "admob.com",
    "admob.google.com",
    "admob.googleapis.com",
    "adservice.google.com",
    "adservices.google.com",
    "adsense.com",
    "analytics.google.com",
    "app-measurement-cn.com",
    "app-measurement.com",
    "apps.admob.com",
    "clients.google.com",
    "dartsearch.net",
    "developers.google.com",
    "doubleclick-cn.net",
    "doubleclick.net",
    "doubleclick.com",
    "firebasedynamiclinks.googleapis.com",
    "firebase.google.com",
    "firebaseinstallations.googleapis.com",
    "firebaseremoteconfig.googleapis.com",
    "g.doubleclick.net",
    "google-analytics-cn.com",
    "google-analytics.com",
    "googleadservices.com",
    "googleads.g.doubleclick.net",
    "googleads.googleapis.com",
    "googleads.com",
    "googleapis.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "gstatic.com",
    "gstaticadssl.l.google.com",
    "pagead.l.doubleclick.net",
    "pagead2.googlesyndication.com",
    "play.googleapis.com",
    "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "support.google.com",
    "t.myvisualiq.net",
    "tpc.googlesyndication.com",
    "adwords.com",
    "clickserve.dartsearch.net",
    "adtrafficquality.google",
    "googletagservices.com",

    "browserleaks.com",
    "aparatvpn.com",
]


# ---------------- توابع کمکی ----------------
def run(cmd):
    print(f"[+] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)


# ---------------- نصب بسته‌ها ----------------
def install_packages():
    run("apt update")
    run("apt install -y wget git ipset build-essential python3-pip")
    run("pip3 install requests")


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


def install_tun2socks():
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


# ---------------- تنظیم interface ----------------
def setup_tun():
    # اگر interface موجود نیست بساز
    run_cmd(f"ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun")
    # اگر IP اضافه نشده است، اضافه کن
    run_cmd(f"ip addr show dev {TUN_DEV} | grep -q '{TUN_ADDR.split('/')[0]}' || ip addr add {TUN_ADDR} dev {TUN_DEV}")
    # مطمئن شو interface up است
    run_cmd(f"ip link set {TUN_DEV} up")


def setup_dnsmasq():
    os.makedirs("/etc/dnsmasq.d", exist_ok=True)

    # upstream DNS
    with open("/etc/dnsmasq.d/upstream.conf", "w") as f:
        f.write("no-resolv\nserver=1.1.1.1\nserver=8.8.8.8\n")

    # VPN DNS listener
    with open("/etc/dnsmasq.d/vpn-dns.conf", "w") as f:
        f.write(f"listen-address=127.0.0.1\nlisten-address=10.8.0.1\nbind-interfaces\ncache-size=10000\n")

    # wildcard دامنه‌ها برای پروکسی (تمام زیر دامنه‌ها)
    with open("/etc/dnsmasq.d/proxy_wildcards.conf", "w") as f:
        for domain in DOMAINS:
            f.write(f"ipset=/{domain}/proxylist\n")

    # ipset برای دامنه‌ها
    run_cmd("ipset create proxylist hash:ip -exist")

    run_cmd("truncate -s 0 /etc/dnsmasq.conf")
    with open("/etc/dnsmasq.conf", "w") as f:
        f.write("conf-dir=/etc/dnsmasq.d,*.conf\n")

    # restart dnsmasq
    run_cmd("systemctl restart dnsmasq")
    run_cmd("systemctl enable dnsmasq")
    print("[+] dnsmasq configured for wildcard proxy domains.")


# ---------------- iptables برای full-route ----------------
def setup_iptables():
    # پاکسازی قوانین قبلی
    run("iptables -t mangle -F PREROUTING")
    run("ip rule del fwmark 1 table tun2socks || true")
    run("ip route flush table tun2socks || true")

    # mark همه ترافیک از VPN subnet (TCP و UDP) برای tun2socks
    run(f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -j MARK --set-mark 1")

    # allow forwarding
    run(f"iptables -A FORWARD -s {VPN_SUBNET} -o {TUN_DEV} -j ACCEPT")
    run(f"iptables -A FORWARD -d {VPN_SUBNET} -i {TUN_DEV} -m state --state RELATED,ESTABLISHED -j ACCEPT")

    # NAT برای outgoing
    run(f"iptables -t nat -A POSTROUTING -o {TUN_DEV} -j MASQUERADE")

    # routing table
    run(f"grep -q '^{PROXY_TABLE} tun2socks' /etc/iproute2/rt_tables || echo '{PROXY_TABLE} tun2socks' >> /etc/iproute2/rt_tables")
    run("ip rule add fwmark 1 table tun2socks")
    run(f"ip route add default via {TUN_ADDR.split('/')[0]} dev {TUN_DEV} table tun2socks")


# ---------------- systemd service ----------------
def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    return url


def create_service():
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

    install_packages()
    setup_dnsmasq()

    install_tun2socks()
    setup_tun()
    setup_iptables()
    create_service()

    run_cmd("""sudo sed -i '/^push "dhcp-option DNS /s/^/#/' /etc/openvpn/server.conf""")
    run_cmd("""sudo systemctl restart openvpn@server""")

    print("[+] آماده شد! تمام ترافیک VPN و WebRTC از طریق SOCKS عبور می‌کند.")


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
