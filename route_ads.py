#!/usr/bin/env python3
import subprocess
import sys
import os
import time

# نصب خودکار پکیج‌ها
print("[+] Installing required packages...")
os.system("sudo apt-get update")
os.system("sudo apt-get install -y python3-pip dnsmasq ipset openvpn")
os.system("sudo pip3 install dnspython")
time.sleep(5)

# دامنه‌ها برای پروکسی
DOMAINS = [
    "aparatvpn.com",
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

# تنظیمات
FORCE_UDP_PROXY = True
TCP_DOMAINS_ONLY = True
SUBDOMAINS = ["www", "api", "ads", "mail", "app", "static", "cdn"]
VPN_SUBNET = "10.8.0.0/20"  # subnet VPN – اگر فرق داره، تغییر بده
VPN_DNS_IP = "10.8.0.1"  # IP tun0 برای DNS push


# غیرفعال کردن systemd-resolved و تنظیم resolv.conf
def disable_systemd_resolved():
    print("[+] Disabling systemd-resolved...")
    try:
        subprocess.run(["sudo", "systemctl", "stop", "systemd-resolved"], check=True)
        subprocess.run(["sudo", "systemctl", "disable", "systemd-resolved"], check=True)
        print("[+] systemd-resolved disabled.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error disabling systemd-resolved: {e}")

    # برداشتن immutable flag و حذف فایل
    resolv_conf = "/etc/resolv.conf"
    if os.path.islink(resolv_conf) or os.path.exists(resolv_conf):
        print("[+] Removing immutable flag from /etc/resolv.conf...")
        subprocess.run(["sudo", "chattr", "-i", resolv_conf], check=False)
        print("[+] Removing existing /etc/resolv.conf...")
        subprocess.run(["sudo", "rm", "-f", resolv_conf], check=True)

    print("[+] Creating new /etc/resolv.conf pointing to dnsmasq (127.0.0.1)...")
    with open(resolv_conf, "w") as f:
        f.write("nameserver 127.0.0.1\n")
    subprocess.run(["sudo", "chattr", "+i", resolv_conf], check=False)
    print("[+] /etc/resolv.conf configured.")


# تنظیم dnsmasq برای upstream و VPN listen
def configure_dnsmasq_for_vpn():
    dnsmasq_conf = "/etc/dnsmasq.conf"
    print("[+] Configuring dnsmasq for upstream DNS and VPN queries...")
    lines_to_add = [
        "server=8.8.8.8\n",
        "server=8.8.4.4\n",
        "interface=tun0\n",
        f"listen-address=127.0.0.1,{VPN_DNS_IP}\n",
        "bind-interfaces\n"
    ]
    # اگر خطوط از قبل نیستن، اضافه کن
    with open(dnsmasq_conf, "r") as f:
        content = f.read()
    for line in lines_to_add:
        if line.strip() not in content:
            with open(dnsmasq_conf, "a") as f:
                f.write(line)
    print("[+] dnsmasq configured for tun0 and upstream DNS.")


# تنظیم OpenVPN برای push DNS به کلاینت‌ها (حذف push قبلی)
def configure_openvpn_dns():
    openvpn_conf = "/etc/openvpn/server.conf"  # اگر مسیر فرق داره، تغییر بده
    print("[+] Configuring OpenVPN to push DNS...")
    push_line = f'push "dhcp-option DNS {VPN_DNS_IP}"\n'
    if os.path.exists(openvpn_conf):
        # خواندن فایل و حذف هرگونه push dhcp-option DNS قبلی
        with open(openvpn_conf, "r") as f:
            lines = f.readlines()
        new_lines = [line for line in lines if not line.strip().startswith('push "dhcp-option DNS')]
        # اضافه کردن push جدید
        new_lines.append(push_line)
        # بازنویسی فایل
        with open(openvpn_conf, "w") as f:
            f.writelines(new_lines)
        print("[+] OpenVPN DNS push configured (previous push removed).")
        run_command(["sudo", "systemctl", "restart", "openvpn@server"], "Error restarting OpenVPN")
    else:
        print(
            f"[!] OpenVPN config file {openvpn_conf} not found. Please add 'push \"dhcp-option DNS {VPN_DNS_IP}\"' manually.")


# تابع برای اجرای دستورات و چاپ خروجی
def run_command(cmd, error_message="Error running command"):
    print(f"[+] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] {error_message}: {' '.join(cmd)}")
        if e.stderr:
            print(e.stderr)


# تابع برای resolve کردن IPهای دامنه (فقط IPv4)
def update_ipset(domain, ipset_name="proxylist"):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # استفاده از Google DNS
    resolver.timeout = 10
    resolver.lifetime = 10
    ips = []

    try:
        answers = resolver.resolve(domain, 'A')  # فقط IPv4
        for rdata in answers:
            ip = rdata.address
            run_command(["sudo", "ipset", "add", ipset_name, ip, "-exist"])
            ips.append(ip)
        print(f"[+] Added {len(ips)} IPv4 IPs for {domain}: {ips}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        print(f"[!] Domain {domain} not found")
    return ips


# تابع اصلی
def main():
    # غیرفعال کردن systemd-resolved
    disable_systemd_resolved()

    # تنظیم dnsmasq برای VPN و upstream
    configure_dnsmasq_for_vpn()

    # تنظیم OpenVPN برای push DNS
    configure_openvpn_dns()

    # آماده‌سازی ipset
    run_command(["sudo", "ipset", "destroy", "proxylist"], "Error destroying ipset")
    run_command(["sudo", "ipset", "create", "proxylist", "hash:ip"], "Error creating ipset")

    # نوشتن تنظیمات dnsmasq
    dnsmasq_conf = "/etc/dnsmasq.d/proxylist.conf"
    print(f"[+] Writing dnsmasq config: {dnsmasq_conf}")
    with open(dnsmasq_conf, "w") as f:
        for domain in DOMAINS:
            f.write(f"ipset=/.{domain}/proxylist\n")
    run_command(["sudo", "chmod", "644", dnsmasq_conf])

    # ری‌استارت dnsmasq
    run_command(["sudo", "systemctl", "restart", "dnsmasq"], "Error restarting dnsmasq")
    run_command(["sudo", "systemctl", "status", "dnsmasq"], "Error checking dnsmasq status")

    # Resolve کردن دامنه‌ها و زیردامنه‌ها (فقط IPv4)
    for domain in DOMAINS:
        print(f"[+] Resolving IPs for {domain} and its subdomains...")
        update_ipset(domain)
        for subdomain in SUBDOMAINS:
            full_domain = f"{subdomain}.{domain}"
            update_ipset(full_domain)

    # تنظیمات iptables
    run_command(["sudo", "iptables", "-t", "mangle", "-F", "PREROUTING"])
    run_command(
        ["sudo", "iptables", "-t", "mangle", "-A", "PREROUTING", "-s", VPN_SUBNET, "-m", "set", "--match-set",
         "proxylist",
         "dst", "-j", "MARK", "--set-mark", "1"])

    # تنظیمات ip route
    run_command(["sudo", "grep", "-q", "^100 redsocks", "/etc/iproute2/rt_tables"], "Error checking rt_tables")
    run_command(["sudo", "sh", "-c", "echo '100 redsocks' >> /etc/iproute2/rt_tables"])
    run_command(["sudo", "ip", "rule", "del", "fwmark", "1", "table", "redsocks"], "Error deleting ip rule")
    run_command(["sudo", "ip", "route", "flush", "table", "redsocks"], "Error flushing ip route")
    run_command(["sudo", "ip", "rule", "add", "fwmark", "1", "table", "redsocks"])
    run_command(["sudo", "ip", "route", "add", "default", "via", "127.0.0.1", "dev", "lo", "table", "redsocks"])

    # تنظیمات NAT برای TCP و UDP
    run_command(["sudo", "iptables", "-t", "nat", "-F", "PREROUTING"])
    run_command(
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-m", "mark", "--mark", "1", "-p", "tcp", "-j",
         "REDIRECT",
         "--to-ports", "12345"])
    if FORCE_UDP_PROXY:
        run_command(
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "tun0", "-p", "udp", "!", "--dport", "53", "-j",
             "REDIRECT", "--to-ports", "12345"])

    print("\n✅ آماده شد!")
    print("تنظیمات فعلی:")
    print(f"  FORCE_UDP_PROXY = {FORCE_UDP_PROXY}")
    print(f"  TCP_DOMAINS_ONLY = {TCP_DOMAINS_ONLY}")
    print(f"  VPN_SUBNET = {VPN_SUBNET}")
    print(f"  VPN_DNS_IP = {VPN_DNS_IP}")
    print("برای تست:")
    for domain in DOMAINS:
        print(f"  dig {domain}")
    print("  sudo ipset list proxylist")


if __name__ == "__main__":
    try:
        main()
        time.sleep(900000)
    except:
        print("-")
