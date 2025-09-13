import subprocess
import sys
import os
import time

# نصب خودکار dnspython اگر نصب نباشد
os.system("sudo pip install dnspython")
os.system("sudo pip3 install dnspython")
os.system("sudo apt-get install -y dnsmasq")
time.sleep(5)

# دامنه‌ها برای پروکسی (لیست نمونه، می‌تونی تغییر بدی)
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


# غیرفعال کردن systemd-resolved و تنظیم resolv.conf
def disable_systemd_resolved():
    print("[+] Disabling systemd-resolved...")
    try:
        subprocess.run(["systemctl", "stop", "systemd-resolved"], check=True)
        subprocess.run(["systemctl", "disable", "systemd-resolved"], check=True)
        print("[+] systemd-resolved disabled.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error disabling systemd-resolved: {e}")

    # حذف symlink و ایجاد resolv.conf جدید
    resolv_conf = "/etc/resolv.conf"
    if os.path.islink(resolv_conf) or os.path.exists(resolv_conf):
        print("[+] Removing existing /etc/resolv.conf...")
        subprocess.run(["rm", "-f", resolv_conf], check=True)

    print("[+] Creating new /etc/resolv.conf with Google DNS...")
    with open(resolv_conf, "w") as f:
        f.write("nameserver 8.8.8.8\n")
        f.write("nameserver 8.8.4.4\n")
    subprocess.run(["chattr", "+i", resolv_conf], check=True)  # قفل کردن فایل
    print("[+] /etc/resolv.conf configured.")


# تابع برای اجرای دستورات و چاپ خروجی
def run_command(cmd, error_message="Error running command"):
    print(f"[+] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] {error_message}: {' '.join(cmd)}")
        print(e.stderr)


# تابع برای resolve کردن IPهای دامنه
def update_ipset(domain, ipset_name="proxylist"):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # استفاده از Google DNS
    resolver.timeout = 10
    resolver.lifetime = 10
    ips = []

    try:
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.address
            run_command(["ipset", "add", ipset_name, ip, "-exist"])
            ips.append(ip)
        print(f"[+] Added {len(ips)} IPs for {domain}: {ips}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        print(f"[!] Domain {domain} not found")
    return ips


# تابع اصلی
def main():
    # غیرفعال کردن systemd-resolved
    disable_systemd_resolved()

    # آماده‌سازی ipset
    run_command(["ipset", "destroy", "proxylist"], "Error destroying ipset")
    run_command(["ipset", "create", "proxylist", "hash:ip"], "Error creating ipset")

    # نوشتن تنظیمات dnsmasq
    dnsmasq_conf = "/etc/dnsmasq.d/proxylist.conf"
    print(f"[+] Writing dnsmasq config: {dnsmasq_conf}")
    with open(dnsmasq_conf, "w") as f:
        for domain in DOMAINS:
            f.write(f"ipset=/.{domain}/proxylist\n")

    # ری‌استارت dnsmasq
    run_command(["systemctl", "restart", "dnsmasq"], "Error restarting dnsmasq")
    run_command(["systemctl", "status", "dnsmasq"], "Error checking dnsmasq status")

    # Resolve کردن دامنه‌ها و زیردامنه‌ها
    for domain in DOMAINS:
        print(f"[+] Resolving IPs for {domain} and its subdomains...")
        update_ipset(domain)
        for subdomain in SUBDOMAINS:
            full_domain = f"{subdomain}.{domain}"
            update_ipset(full_domain)

    # تنظیمات iptables
    run_command(["iptables", "-t", "mangle", "-F", "PREROUTING"])
    run_command(
        ["iptables", "-t", "mangle", "-A", "PREROUTING", "-s", "10.8.0.0/20", "-m", "set", "--match-set", "proxylist",
         "dst", "-j", "MARK", "--set-mark", "1"])

    # تنظیمات ip route
    run_command(["grep", "-q", "^100 redsocks", "/etc/iproute2/rt_tables"], "Error checking rt_tables")
    run_command(["sh", "-c", "echo '100 redsocks' >> /etc/iproute2/rt_tables"])
    run_command(["ip", "rule", "del", "fwmark", "1", "table", "redsocks"], "Error deleting ip rule")
    run_command(["ip", "route", "flush", "table", "redsocks"], "Error flushing ip route")
    run_command(["ip", "rule", "add", "fwmark", "1", "table", "redsocks"])
    run_command(["ip", "route", "add", "default", "via", "127.0.0.1", "dev", "lo", "table", "redsocks"])

    # تنظیمات NAT برای TCP و UDP
    run_command(["iptables", "-t", "nat", "-F", "PREROUTING"])
    run_command(
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-m", "mark", "--mark", "1", "-p", "tcp", "-j", "REDIRECT",
         "--to-ports", "12345"])
    if FORCE_UDP_PROXY:
        run_command(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "tun0", "-p", "udp", "!", "--dport", "53", "-j",
                     "REDIRECT", "--to-ports", "12345"])

    print("\n✅ آماده شد!")
    print("تنظیمات فعلی:")
    print(f"  FORCE_UDP_PROXY = {FORCE_UDP_PROXY}")
    print(f"  TCP_DOMAINS_ONLY = {TCP_DOMAINS_ONLY}")
    print("برای تست:")
    for domain in DOMAINS:
        print(f"  dig {domain}")
    print("  sudo ipset list proxylist")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script must be run as root (sudo).")
        sys.exit(1)
    main()
