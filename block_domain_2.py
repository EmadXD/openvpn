# wget --backups=1 https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/block_domain.py -P /root/ && chmod 777 * && pm2 start "python3.8 block_domain.py" && pm2 save && pm2 startup && pm2 save
# wget --backups=1 https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/block_domain_2.py -P /root/ && chmod 777 * && pm2 start "python3.8 block_domain_2.py" && pm2 save && pm2 startup && pm2 save


import os

os.system("apt install python3-pip -y")
os.system("pip install dnspython")
import time

import os
import socket
import dns.resolver


def get_ips_from_domain(domain):
    """
    Get a list of IP addresses for the given domain.
    """
    ips = []

    # Using socket (basic) to get IPs
    try:
        addr_info = socket.getaddrinfo(domain, None)
        for res in addr_info:
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        print(f"Error resolving domain {domain} using socket.")

    # Using dns.resolver (advanced) to get all IPs
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.to_text()
            if ip not in ips:
                ips.append(ip)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"Error resolving domain {domain} using dns.resolver.")

    return ips


def block_ips(ips):
    """
    Block the given list of IP addresses using iptables.
    """
    for ip in ips:
        # Construct iptables command to block the IP
        command = f"/sbin/iptables -I FORWARD 1 -i as+ -d {ip} -j DROP"
        print(f"Blocking IP: {ip}")
        os.system(command)  # Execute the iptables command


while True:
    domain_list = ["facebook.com", "instagram.com", "fbcdn.com", "fbcdn.net"]
    os.system("sudo apt update -y")
    os.system("sudo apt install whois -y")
    for domain in domain_list:
        ip_list = get_ips_from_domain(domain)
        if ip_list:
            print(f"Found IPs for {domain}: {', '.join(ip_list)}")
            # Block each IP
            block_ips(ip_list)
        else:
            print(f"No IPs found for {domain}.")

    # -------------telegram
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.4.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.8.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.16.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.12.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 149.154.160.0/20 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.105.192.0/23 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.20.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 185.76.151.0/24 -j DROP")
    time.sleep(300)  # --10 minutes
