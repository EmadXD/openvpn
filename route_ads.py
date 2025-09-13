#!/usr/bin/env python3
import os
import subprocess
import sys
import socket
import dns.resolver

# 🔹 تنظیمات
IPSET_NAME = "proxylist"
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
VPN_SUBNET = "10.8.0.0/20"
REDSOCKS_PORT = 12345
PROXY_TABLE = "100"
DNSMASQ_CONF = "/etc/dnsmasq.d/proxylist.conf"

# 🔹 سوییچ‌ها
FORCE_UDP_PROXY = True
TCP_DOMAINS_ONLY = True

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
    run_cmd(f"ipset create {IPSET_NAME} hash:ip || true")

def configure_dnsmasq():
    """نوشتن wildcard دامنه‌ها در dnsmasq برای پشتیبانی از زیردامنه‌های متغیر"""
    print(f"[+] Writing dnsmasq config: {DNSMASQ_CONF}")
    with open(DNSMASQ_CONF, "w") as f:
        for domain in DOMAINS:
            # تنظیم dnsmasq برای هدایت تمام زیردامنه‌ها به ipset
            f.write(f"ipset=/.{domain}/{IPSET_NAME}\n")
    run_cmd("systemctl restart dnsmasq")

def update_ipset():
    """resolve دستی دامنه‌ها و زیردامنه‌ها برای گرفتن IP"""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for domain in DOMAINS:
        print(f"[+] Resolving IPs for {domain} and its subdomains...")
        try:
            # Resolve دامنه اصلی
            answers = resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            for ip in ips:
                run_cmd(f"ipset add {IPSET_NAME} {ip} -exist")
            if ips:
                print(f"[+] Added {len(ips)} IPs for {domain}: {ips}")

            # تلاش برای پیدا کردن زیردامنه‌های متداول
            common_subdomains = ['www', 'api', 'ads', 'mail', 'app', 'static', 'cdn']
            for subdomain in common_subdomains:
                try:
                    sub_domain = f"{subdomain}.{domain}"
                    answers = resolver.resolve(sub_domain, 'A')
                    sub_ips = [str(rdata) for rdata in answers]
                    for ip in sub_ips:
                        run_cmd(f"ipset add {IPSET_NAME} {ip} -exist")
                    if sub_ips:
                        print(f"[+] Added {len(sub_ips)} IPs for {sub_domain}: {sub_ips}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    print(f"[!] Subdomain {sub_domain} not found")
                except Exception as e:
                    print(f"[!] Error resolving {sub_domain}: {e}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print(f"[!] Domain {domain} not found")
        except Exception as e:
            print(f"[!] Error resolving {domain}: {e}")

def setup_iptables_fwmark():
    """اضافه کردن mark به ترافیک VPN برای دامنه‌ها"""
    run_cmd("iptables -t mangle -F PREROUTING")
    if TCP_DOMAINS_ONLY:
        run_cmd(f"iptables -t mangle -A PREROUTING -s {VPN_SUBNET} "
                f"-m set --match-set {IPSET_NAME} dst -j MARK --set-mark 1")

def setup_routing_table():
    """اضافه کردن routing table برای ترافیک mark شده"""
    run_cmd(f"grep -q '^{PROXY_TABLE} redsocks' /etc/iproute2/rt_tables "
            f"|| echo '{PROXY_TABLE} redsocks' >> /etc/iproute2/rt_tables")
    run_cmd(f"ip rule del fwmark 1 table redsocks || true")
    run_cmd(f"ip route flush table redsocks || true")
    if TCP_DOMAINS_ONLY:
        run_cmd(f"ip rule add fwmark 1 table redsocks")
        run_cmd(f"ip route add default via 127.0.0.1 dev lo table redsocks")

def setup_iptables_redirect():
    """REDIRECT به پروکسی بسته به تنظیمات"""
    run_cmd("iptables -t nat -F PREROUTING")
    if TCP_DOMAINS_ONLY:
        run_cmd(f"iptables -t nat -A PREROUTING -m mark --mark 1 -p tcp "
                f"-j REDIRECT --to-ports {REDSOCKS_PORT}")
    if FORCE_UDP_PROXY:
        run_cmd(f"iptables -t nat -A PREROUTING -i tun0 -p udp ! --dport 53 "
                f"-j REDIRECT --to-ports {REDSOCKS_PORT}")

def main():
    if os.geteuid() != 0:
        print("[!] لطفاً اسکریپت را با sudo اجرا کنید")
        sys.exit(1)

    setup_ipset()
    configure_dnsmasq()
    update_ipset()
    setup_iptables_fwmark()
    setup_routing_table()
    setup_iptables_redirect()

    print("\n✅ آماده شد!")
    print("تنظیمات فعلی:")
    print(f"  FORCE_UDP_PROXY = {FORCE_UDP_PROXY}")
    print(f"  TCP_DOMAINS_ONLY = {TCP_DOMAINS_ONLY}")
    print("برای تست:")
    for domain in DOMAINS:
        print(f"  dig {domain}")
    print("  sudo ipset list proxylist")

if __name__ == "__main__":
    main()
