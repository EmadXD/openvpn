#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import requests
import time

# ---------------- تنظیمات ----------------
IPSET_NAME = "proxylist"
VPN_SUBNET = "10.8.0.0/14"
PROXY_TABLE = "100"
TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"
use_binary_created = True

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
    "firebase.google.com",
    "g.doubleclick.net",
    "google-analytics.com",
    "googleadservices.com",
    "googleads.com",
    "googleapis.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "gstatic.com",
    "pagead2.googlesyndication.com",
    "play.googleapis.com",
    "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "support.google.com",
    "tpc.googlesyndication.com",
    "partner.googleadservices.com",
    "stats.g.doubleclick.net",
    "pagead.l.doubleclick.net",
    "googleusercontent.com",
    "ssl.google-analytics.com",

    "browserleaks.com", "aparatvpn.com",

    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
]

FULL_ROUTE_TO_PROXY = True
block_udp = True


# ---------------- Helpers ----------------
def run_cmd(cmd):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True,
                                capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {cmd}")
        if e.stderr:
            print(e.stderr.strip())


def run_cmd_return(cmd):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        output = result.stdout if result.stdout else ""
        print(output, end="")  # نشان دادن در ترمینال
        return output  # برگرداندن همان خروجی

    except subprocess.CalledProcessError as e:
        error = e.stderr if e.stderr else ""
        print(error, end="")  # چاپ مثل ترمینال
        return error  # برگرداندن همان متن خطا


# ---------------- Install Packages ----------------
def setup_install_packages():
    tun2socks_path = "/opt/tun2socks"

    tun2socks_installed = os.path.exists(tun2socks_path)

    if tun2socks_installed:
        size_bytes = os.path.getsize(tun2socks_path)
        size_mb = size_bytes / (1024 * 1024)
    else:
        size_mb = 0

    if size_mb >= 11:
        print("[+] tun2socks قبلاً نصب شده است، از مرحله نصب عبور می‌کنیم.")
        return

    print("[+] Installing required packages and building tun2socks...")
    run_cmd("sudo apt update")
    run_cmd("sudo apt install -y wget git make ipset build-essential shadowsocks-libev python3-pip dnsmasq")
    run_cmd("pip3 install requests")

    # نصب Go
    run_cmd("wget https://aparatvpn.com/go1.23.1.linux-amd64.tar.gz -O /tmp/go1.23.1.linux-amd64.tar.gz")
    run_cmd("rm -rf /usr/local/go")
    run_cmd("tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz")
    os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]

    # ساخت tun2socks
    if use_binary_created:
        run_cmd("sudo mkdir -p /opt/")
        run_cmd("sudo rm -rf /opt/tun2socks")
        run_cmd("sudo wget https://aparatvpn.com/tun2socks -O /opt/tun2socks")
        run_cmd("sudo chmod 777 /opt/tun2socks")
    else:
        run_cmd("rm -rf tun2socks")
        run_cmd("git clone https://github.com/xjasonlyu/tun2socks.git")
        os.chdir("tun2socks")
        run_cmd("make tun2socks")
        run_cmd("cp ./build/tun2socks /usr/local/bin")
        os.chdir("..")
    # ------------- check again
    tun2socks_installed = os.path.exists(tun2socks_path)
    if tun2socks_installed:
        size_bytes = os.path.getsize(tun2socks_path)
        size_mb = size_bytes / (1024 * 1024)
    else:
        size_mb = 0

    if size_mb < 11:
        setup_install_packages()
    else:
        print("[+] Installation completed successfully.")


# ---------------- ipset ----------------
def setup_ipset():
    run_cmd(f"ipset destroy {IPSET_NAME} || true")
    run_cmd(f"ipset create {IPSET_NAME} hash:ip")


# ---------------- dnsmasq ----------------
def setup_dnsmasq():
    from subprocess import run
    def run_cmd(cmd):
        run(cmd, shell=True, check=False)

    # ---------------- main dnsmasq.conf ----------------
    dnsmasq_main = """port=53
listen-address=127.0.0.1,10.8.0.1
bind-interfaces
conf-dir=/etc/dnsmasq.d/,*.conf
"""
    with open("/etc/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_main)

    # ---------------- ipset.conf ----------------
    with open("/etc/dnsmasq.d/ipset.conf", "w") as f:
        for domain in DOMAINS:
            f.write(f"ipset=/{domain}/{IPSET_NAME}\n")

    # ---------------- openvpn_dns.conf ----------------
    dns_openvpn = """interface=tun0
listen-address=10.8.0.1
server=127.0.0.53
"""
    dns_openvpn = """interface=tun0
listen-address=10.8.0.1
server=1.1.1.1
server=1.0.0.1
"""
    with open("/etc/dnsmasq.d/openvpn_dns.conf", "w") as f:
        f.write(dns_openvpn)

    # ---------------- restart dnsmasq ----------------
    run_cmd("systemctl restart dnsmasq")


# ---------------- tun2socks interface ----------------
def setup_tun2socks_interface():
    run_cmd(f"ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun")
    run_cmd(f"ip addr show dev {TUN_DEV} | grep -q '{TUN_ADDR.split('/')[0]}' || ip addr add {TUN_ADDR} dev {TUN_DEV}")
    run_cmd(f"ip link set {TUN_DEV} up")


# ---------------- iptables ----------------
def setup_vpn_forwarding():
    run_cmd(f"iptables -A FORWARD -s {VPN_SUBNET} -o {TUN_DEV} -j ACCEPT")
    run_cmd(f"iptables -A FORWARD -d {VPN_SUBNET} -i {TUN_DEV} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run_cmd(f"iptables -t nat -A POSTROUTING -o {TUN_DEV} -s {VPN_SUBNET} -j MASQUERADE")


def setup_iptables_fwmark():
    run_cmd("iptables -t mangle -F PREROUTING")
    if FULL_ROUTE_TO_PROXY:
        run_cmd(
            f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")
    else:
        run_cmd(
            f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -p tcp -m multiport --dports 80,443,8080,8443 -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")

    if block_udp:
        run_cmd("iptables -t mangle -A PREROUTING -s 10.8.0.0/14 -p udp -m mark --mark 1 -j DROP")


def setup_tun2socks_routing():
    run_cmd(
        f"grep -q '^{PROXY_TABLE} tun2socks' /etc/iproute2/rt_tables || echo '{PROXY_TABLE} tun2socks' >> /etc/iproute2/rt_tables"
    )
    run_cmd("ip rule del fwmark 1 table tun2socks || true")
    run_cmd("ip route flush table tun2socks || true")
    run_cmd("ip rule add fwmark 1 table tun2socks")
    run_cmd(f"ip route add default via {TUN_ADDR.split('/')[0]} dev {TUN_DEV} table tun2socks")


# ---------------- systemd tun2socks ----------------
def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    return url.rstrip('/')


def create_systemd_service():
    global SOCKS_PROXY
    try:
        SOCKS_PROXY = clean_proxy_url(
            requests.get("https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php").text
        )
    except:
        print("[!] Proxy fetch failed, using default.")

    service_content = f"""
[Unit]
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

    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable --now tun2socks.service")
    run_cmd("systemctl restart tun2socks.service")


# ---------------- main ----------------
def main():
    if os.geteuid() != 0:
        print("[!] لطفاً با sudo اجرا کنید.")
        sys.exit(1)

    time.sleep(2)

    setup_install_packages()
    setup_ipset()
    setup_dnsmasq()
    setup_tun2socks_interface()
    setup_vpn_forwarding()
    setup_iptables_fwmark()
    setup_tun2socks_routing()
    create_systemd_service()

    run_cmd("sudo systemctl stop systemd-resolved")
    run_cmd("sudo systemctl disable --now systemd-resolved")
    run_cmd("sudo rm -f /etc/resolv.conf")
    run_cmd('echo "nameserver 10.8.0.1" | sudo tee /etc/resolv.conf')

    run_cmd(
        """sudo sed -i.bak '/^push "dhcp-option DNS/d' /etc/openvpn/server.conf && \
echo 'push "dhcp-option DNS 10.8.0.1"' | sudo tee -a /etc/openvpn/server.conf
""")
    time.sleep(2)
    run_cmd("""sudo systemctl restart openvpn@server""")
    print("\n[+] آماده شد! سیستم‌دی‌ان‌اس اصلی فعال است و فقط دامنه‌های خاص از tun2socks عبور می‌کنند.")


if __name__ == "__main__":
    try:
        time.sleep(10)
        main()
        time.sleep(90000000)
    except KeyboardInterrupt:
        time.sleep(90000000)
        print("خروج کاربر...")
    except Exception as e:
        time.sleep(90000000)
        print(f"خطا: {e}")
