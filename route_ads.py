#!/usr/bin/env python3
import os
import subprocess
import sys

# 🔹 تنظیمات
IPSET_NAME = "proxylist"
DNSMASQ_CONF = "/etc/dnsmasq.d/proxylist.conf"
VPN_SUBNET = "10.8.0.0/20"
REDSOCKS_PORT = 12345

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
    "tpc.googlesyndication.com"
]

FORCE_UDP_PROXY = True
TCP_DOMAINS_ONLY = True


def run_cmd(cmd, ignore_error=False):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        if result.stdout.strip():
            print(result.stdout.strip())
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not ignore_error:
            print(f"[!] Error: {e.stderr.strip()}")
        return None


def install_packages():
    pkgs = ["iptables", "ipset", "dnsutils", "dnsmasq"]
    run_cmd("apt-get update -y", ignore_error=True)
    run_cmd("apt-get install -y " + " ".join(pkgs))


def setup_dnsmasq():
    """تنظیم dnsmasq روی پورت 5353 و اضافه کردن ipset rules"""
    lines = [
        "port=5353",
        "listen-address=127.0.0.1",
        "bind-interfaces"
    ]

    for domain in DOMAINS:
        lines.append(f"ipset=/{domain}/{IPSET_NAME}")

    os.makedirs("/etc/dnsmasq.d", exist_ok=True)
    with open(DNSMASQ_CONF, "w") as f:
        f.write("\n".join(lines) + "\n")

    run_cmd("systemctl restart dnsmasq")


def setup_ipset():
    run_cmd(f"ipset destroy {IPSET_NAME} || true", ignore_error=True)
    run_cmd(f"ipset create {IPSET_NAME} hash:ip")


def setup_iptables():
    run_cmd("iptables -t mangle -F PREROUTING")
    run_cmd("iptables -t nat -F PREROUTING")

    if TCP_DOMAINS_ONLY:
        run_cmd(f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} "
                f"-m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")
        run_cmd(f"iptables -t nat -A PREROUTING -m mark --mark 1 -p tcp "
                f"-j REDIRECT --to-ports {REDSOCKS_PORT}")

    if FORCE_UDP_PROXY:
        run_cmd(f"iptables -t nat -A PREROUTING -i tun0 -p udp ! --dport 53 "
                f"-j REDIRECT --to-ports {REDSOCKS_PORT}")


def main():
    if os.geteuid() != 0:
        print("[!] لطفاً اسکریپت را با sudo اجرا کنید")
        sys.exit(1)

    install_packages()
    setup_ipset()
    setup_dnsmasq()
    setup_iptables()

    print("\n✅ آماده شد!")
    print("برای تست:")
    for domain in DOMAINS:
        print(f"  dig @{ '127.0.0.1' } -p 5353 {domain}")
    print("  sudo ipset list proxylist")


if __name__ == "__main__":
    main()
