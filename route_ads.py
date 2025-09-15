#!/usr/bin/env python3
import os
import subprocess
import sys
import time

# 🔹 تنظیمات
IPSET_NAME = "proxylist"
DOMAINS = ["browserleaks.com",
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
           "tpc.googlesyndication.com", ]  # 👉 اینجا دامنه‌ها رو وارد کن
VPN_SUBNET = "10.8.0.0/20"
REDSOCKS_PORT = 12345
PROXY_TABLE = "100"  # شماره routing table برای پروکسی

# Google IP ranges برای پوشش کامل 1e100.net
GOOGLE_RANGES = ['8.8.4.0/24', '8.8.8.0/24', '8.34.208.0/20', '8.35.192.0/20', '23.236.48.0/20', '23.251.128.0/19',
                 '34.0.0.0/15', '34.2.0.0/16', '34.3.0.0/23', '34.3.3.0/24', '34.3.4.0/24', '34.3.8.0/21',
                 '34.3.16.0/20', '34.3.32.0/19', '34.3.64.0/18', '34.4.0.0/14', '34.8.0.0/13', '34.16.0.0/12',
                 '34.32.0.0/11', '34.64.0.0/10', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/14', '35.196.0.0/15',
                 '35.198.0.0/16', '35.199.0.0/17', '35.199.128.0/18', '35.200.0.0/13', '35.208.0.0/12', '35.224.0.0/12',
                 '35.240.0.0/13', '57.140.192.0/18', '64.15.112.0/20', '64.233.160.0/19', '66.22.228.0/23',
                 '66.102.0.0/20', '66.249.64.0/19', '70.32.128.0/19', '72.14.192.0/18', '74.114.24.0/21',
                 '74.125.0.0/16', '104.154.0.0/15', '104.196.0.0/14', '104.237.160.0/19', '107.167.160.0/19',
                 '107.178.192.0/18', '108.59.80.0/20', '108.170.192.0/18', '108.177.0.0/17', '130.211.0.0/16',
                 '136.22.160.0/20', '136.22.176.0/21', '136.22.184.0/23', '136.22.186.0/24', '136.124.0.0/15',
                 '142.250.0.0/15', '146.148.0.0/17', '152.65.208.0/22', '152.65.214.0/23', '152.65.218.0/23',
                 '152.65.222.0/23', '152.65.224.0/19', '162.120.128.0/17', '162.216.148.0/22', '162.222.176.0/21',
                 '172.110.32.0/21', '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16', '173.255.112.0/20',
                 '192.104.160.0/23', '192.158.28.0/22', '192.178.0.0/15', '193.186.4.0/24', '199.36.154.0/23',
                 '199.36.156.0/24', '199.192.112.0/22', '199.223.232.0/21', '207.223.160.0/20', '208.65.152.0/22',
                 '208.68.108.0/22', '208.81.188.0/22', '208.117.224.0/19', '209.85.128.0/17', '216.58.192.0/19',
                 '216.73.80.0/20', '216.239.32.0/19', '216.252.220.0/22']
GOOGLE_RANGES = ["64.233.160.0/19",
                 "66.102.0.0/20",
                 "66.249.80.0/20",
                 "72.14.192.0/18",
                 "74.125.0.0/16",
                 "108.177.8.0/21",
                 "142.250.0.0/15",
                 "172.217.0.0/19",
                 "172.253.0.0/16",
                 "173.194.0.0/16",
                 "209.85.128.0/17",
                 "216.58.192.0/19",
                 "216.239.32.0/19", ]


def run_cmd(cmd):
    """اجرای دستور و نمایش خروجی"""
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running command: {cmd}")
        if e.stderr:
            print(e.stderr.strip())


def setup_ipset():
    """ساخت یا پاک کردن ipset"""
    run_cmd(f"ipset destroy {IPSET_NAME} || true")
    run_cmd(f"ipset create {IPSET_NAME} hash:net || true")  # تغییر به hash:net برای رنج‌ها


def add_google_ranges_to_ipset():
    """اضافه کردن رنج‌های Google به ipset برای 1e100.net"""
    print("[+] Adding Google IP ranges to ipset for 1e100.net coverage...")
    for range_cidr in GOOGLE_RANGES:
        run_cmd(f"ipset add {IPSET_NAME} {range_cidr} -exist")


def update_ipset():
    """آی‌پی‌های دامنه‌ها را resolve و داخل ipset قرار دهد"""
    for domain in DOMAINS:
        print(f"[+] Resolving IPs for {domain}...")
        try:
            result = subprocess.run(f"dig +short {domain}", shell=True, check=True, capture_output=True, text=True)
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if not ips:
                print(f"[!] هیچ IP برای {domain} پیدا نشد.")
                continue
            for ip in ips:
                run_cmd(f"ipset add {IPSET_NAME} {ip} -exist")
            print(f"[+] {len(ips)} IPs added for {domain}: {ips}")
        except Exception as e:
            print(f"[!] Error resolving {domain}: {e}")


def setup_iptables_fwmark():
    """اضافه کردن mark به ترافیک VPN برای دامنه‌ها"""
    run_cmd("iptables -t mangle -F PREROUTING")
    run_cmd(
        f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} -m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")


def setup_routing_table():
    """اضافه کردن routing table برای ترافیک mark شده"""
    run_cmd(
        f"grep -q '^{PROXY_TABLE} redsocks' /etc/iproute2/rt_tables || echo '{PROXY_TABLE} redsocks' >> /etc/iproute2/rt_tables")
    run_cmd(f"ip rule del fwmark 1 table redsocks || true")
    run_cmd(f"ip route flush table redsocks || true")
    run_cmd(f"ip rule add fwmark 1 table redsocks")
    run_cmd(f"ip route add default via 127.0.0.1 dev lo table redsocks")


def setup_iptables_redirect():
    """REDIRECT ترافیک mark شده به پورت redsocks"""
    run_cmd("iptables -t nat -F PREROUTING")
    run_cmd(f"iptables -t nat -A PREROUTING -m mark --mark 1 -p tcp -j REDIRECT --to-ports {REDSOCKS_PORT}")
    run_cmd(f"iptables -t nat -A PREROUTING -m mark --mark 1 -p udp -j REDIRECT --to-ports {REDSOCKS_PORT}")


def main():
    if os.geteuid() != 0:
        print("[!] لطفاً اسکریپت را با sudo اجرا کنید")
        sys.exit(1)

    setup_ipset()
    add_google_ranges_to_ipset()  # اضافه کردن رنج‌های Google قبل از resolve
    update_ipset()
    setup_iptables_fwmark()
    setup_routing_table()
    setup_iptables_redirect()

    print("\n✅ آماده شد!")
    print("اکنون فقط ترافیک دامنه‌های لیست‌شده و رنج‌های 1e100.net از پروکسی عبور می‌کند.")
    print("برای تست:")
    for domain in DOMAINS:
        print(f"  dig {domain}")
    print("  sudo ipset list proxylist")


if __name__ == "__main__":
    try:
        main()
        time.sleep(9000000)
    except:
        print("00")
