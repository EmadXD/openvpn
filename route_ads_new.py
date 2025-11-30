import json
import platform
import re

import netaddr
import paramiko as paramiko
import yaml

import time
import sys

import requests as requests
import os, sys

from faker import Faker

from multi_server_manager import *

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from config import *
import mysql.connector

use_udp_shadowsocks = True
create_out_traffic_ads_socks5 = True
# out_traffic_socks5_ip = "91.107.156.205"
# out_traffic_socks5_ip = "socks5.aparatvpn.com"
# out_traffic_socks5_ip = "127.0.0.1"
# out_traffic_socks5_ip = "residential-unlimited-397730.lightningproxies.net"
# out_traffic_socks5_ip = select_("SELECT * FROM splash_vpn ORDER BY RAND() LIMIT 1")[0]['ip']
out_traffic_socks5_ip = random.choice(["socks1.aparatvpn.com", "socks2.aparatvpn.com", "socks3.aparatvpn.com"])
out_traffic_socks5_ip = "socks_main.aparatvpn.com"

# use_abcs5proxy = True

route_ads = "route_ads_new.py"
# if use_abcs5proxy:
#     route_ads = "route_ads_abcs5proxy.py"

# out_traffic_socks5_port = 2083
# out_traffic_socks5_port = 9050
# out_traffic_socks5_port = 2510
out_traffic_socks5_port = 1080

use_redsocks = False

install_socks5_proxy = False
enable_dns_custom = False
server_type_dns_custom = "hetzner"
enable_anti_synflood_ovh = False

force_create_v2ray = False

namecheap_auto = False
use_ipv6 = False
faker = Faker()
# -----
ip_rout_dont_use_vpn_client = [

]
ip_rout_dont_use_vpn_server = [

]
# -----
import netaddr
import ipaddress

ip_list = [
    # "10.0.0.0/8",
    # "172.16.0.0/12",
    # "192.168.0.0/16",
    # "100.64.0.0/10",
    # "198.18.0.0/15",
    # "169.254.0.0/16",
    # -------ArvanCloud
    "185.143.232.0/22",
    "188.229.116.16/29",
    "94.101.182.0/27",
    "2.144.3.128/28",
    "89.45.48.64/28",
    "37.32.16.0/27",
    "37.32.17.0/27",
    "37.32.18.0/27",
    "37.32.19.0/27",
    "185.215.232.0/22",
    # -------CloudFlare
    # -----ipv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

firewall_ip_list_deny_out = ip_list.copy()


def convert_to_net_gateway(ip_mask):
    ip, mask_length = ip_mask.split('/')
    net_gateway = f"{ip} {ipaddress.IPv4Network(ip_mask, strict=False).netmask}"
    return net_gateway


for network in ip_list:
    res_ = convert_to_net_gateway(f"{network}")
    try:
        firewall_ip_list_deny_out.remove(f"{network}")
    except:
        continue
    sub_cidr = netaddr.iprange_to_cidrs(res_.split(" ")[0], res_.split(" ")[1])
    for ci in sub_cidr:
        if f"{ci}" in firewall_ip_list_deny_out:
            firewall_ip_list_deny_out.remove(f"{ci}")
    firewall_ip_list_deny_out.append(f"{network}")

# ------------------------------------------
v2ray_config = """{
  "inbounds": [
    {
      "tag": "xd.json",
      "port": 8080,
      "listen": "0.0.0.0",
      "protocol": "vmess",
      "mux": {
        "concurrency": 8,
        "enabled": true
      },
      "settings": {
        "domainStrategy": "UseIPv4",
        "clients": [
          {
            "id": "6515d80a-a2ae-4703-85b9-a70760fc9a21"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "tcpSettings": {
          "header": {
            "type": "none"
          }
        }
      },
      "sniffing": {
        "enabled": false
      }
    }
  ]
}"""


# -----------------------------------------------------------------------------------------------------------------------
def insert_(query):
    # ------------------------------------------------------------------------------------------------------------------
    connection = mysql.connector.connect(host=vpn_database_config['host'], user=vpn_database_config['user'],
                                         passwd=vpn_database_config['passwd'], database=vpn_database_config['database'])
    mycursor = connection.cursor()
    mycursor.execute('SET NAMES utf8mb4')
    mycursor.execute("SET CHARACTER SET utf8mb4")
    mycursor.execute("SET character_set_connection=utf8mb4")
    # ------------------------------------------------------------------------------------------------------------------
    mycursor.execute(query)
    connection.commit()
    connection.close()


def delete_(query):
    # ------------------------------------------------------------------------------------------------------------------
    connection = mysql.connector.connect(host=vpn_database_config['host'], user=vpn_database_config['user'],
                                         passwd=vpn_database_config['passwd'], database=vpn_database_config['database'])
    mycursor = connection.cursor(buffered=True)
    mycursor.execute('SET NAMES utf8mb4')
    mycursor.execute("SET CHARACTER SET utf8mb4")
    mycursor.execute("SET character_set_connection=utf8mb4")
    # ------------------------------------------------------------------------------------------------------------------
    mycursor.execute(query)
    connection.commit()
    connection.close()
    # ------------------------------------------------------------------------------------------------------------------


def log_channel(chan):
    full_res_ = ""
    try:
        while chan.recv_ready():
            resp = chan.recv(9999)
            print(resp.decode())
            full_res_ += f"{resp.decode()}"
    except Exception as e:
        print(e)
        full_res_ += f"{e}"
    return full_res_


def wait_for_result_channel(chan):
    while not chan.recv_ready():
        print("wait for result ...")
        time.sleep(15)
    while chan.recv_ready():
        resp = chan.recv(9999)
        print(resp.decode())


def create_psk_secret():
    import string
    import random

    # Define the length of the PSK secret
    SECRET_LENGTH = 32

    # Define the characters to use for the PSK secret
    SECRET_CHARS = string.ascii_letters + string.digits

    # Generate a random PSK secret
    psk_secret = ''.join(random.choice(SECRET_CHARS) for i in range(SECRET_LENGTH))
    return f"587:{psk_secret}"


def install_script(ip_, username_, passwd_, tunnel_api_key_, package_, account_id_, id_key_, chat_id_,
                   splash_vpn="no",
                   type='linode',
                   isp='all', sni='raw.githubusercontent.com',
                   domain_cloudflare='null'):
    ssh = paramiko.SSHClient()

    print("=======================================================")
    print(f'ip: {ip_} | username: {username_} | password: {passwd_}')
    # ----------------
    if tunnel_api_key_ == "self":
        tunnel_api_key_ = f"self={ip_}"
    # ----------------
    send_message_telegram(f'=ip: {ip_} | username: {username_} | password: {passwd_}', chat_id_)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if f"{passwd_}" == "null":
        try:
            if f"{platform.system()}".lower() == "windows" or f"{platform.system()}".lower() == "darwin":
                k = paramiko.RSAKey.from_private_key_file(f"./private_key")
            else:
                k = paramiko.RSAKey.from_private_key_file(f"{SERVICE_DIR}/private_key")

            ssh.connect(hostname=ip_, username=username_, pkey=k, timeout=10, banner_timeout=10, auth_timeout=10)

        except Exception as e:
            print(f"{e}::::")
            ssh.connect(hostname=ip_, username=username_, password="*141*11#eEe", look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)
            print(f"Starting: {ip_} {username_} {passwd_} {chat_id_}")
            chan = ssh.invoke_shell()
            chan.send(f'*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            if username_ == "root":
                chan.send('sudo passwd\n')
            else:
                chan.send(f'sudo passwd *141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            # ----
            try:
                ssh.close()
            except:
                print("--")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_, username=username_, password='*141*11#eEe', look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)

    else:
        try:
            ssh.connect(hostname=ip_, username=username_, password=passwd_, look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)
            print(f"Starting: {ip_} {username_} {passwd_} {chat_id_}")
            chan = ssh.invoke_shell()
            chan.send(f'{passwd_}\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            if username_ == "root":
                chan.send('sudo passwd\n')
            else:
                chan.send(f'sudo passwd {username_}\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            # ----
            try:
                ssh.close()
            except:
                print("--")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_, username=username_, password='*141*11#eEe', look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)

        except:
            ssh.connect(hostname=ip_, username=username_, password="*141*11#eEe", look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)
            print(f"Starting: {ip_} {username_} *141*11#eEe {chat_id_}")
            chan = ssh.invoke_shell()
            chan.send(f'*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            if username_ == "root":
                chan.send('sudo passwd\n')
            else:
                chan.send(f'sudo passwd {username_}\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            chan.send('*141*11#eEe\n')
            time.sleep(5)
            # ----
            try:
                ssh.close()
            except:
                print("--")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_, username=username_, password='*141*11#eEe', look_for_keys=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)

    print("=======================================================2")
    # =================================================
    command_list = [
        f"sudo killall apt apt-get",
        f"sudo rm -rf /var/lib/apt/lists/lock",
        f"sudo rm -rf /var/cache/apt/archives/lock",
        f"sudo rm -rf /var/lib/dpkg/lock*",
        f"sudo rm -rf /var/lib/dpkg/lock-frontend",
        f"sudo dpkg --configure -a",
        f"sudo systemctl stop openvpnas",
        f"sudo apt --fix-broken install -y",
        f"sudo killall -9 dpkg",
        f"sudo killall -9 apt-get",
        f"sudo apt --fix-broken install -y",
        f'sudo apt-get update -y',
        f'sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y',
        f"sudo rm -rf /root/*.sh",
        f"sudo apt purge openvpn -y",
        f"sudo apt-get remove openvpn -y",
        f"sudo apt-get remove --auto-remove openvpn -y",
        f"sudo apt purge openvpn-as -y",
        f"sudo apt-get remove openvpn-as -y",
        f"sudo apt-get remove --auto-remove openvpn-as -y",
        f"sudo rm -rf /root/*.ovpn",
        f"sudo rm -rf /home/{username_}/*.ovpn",
        f"sudo rm -rf /etc/openvpn",
        f"sudo rm -rf /usr/local/openvpn_as",
        f"sudo rm -rf /root/openvpn",
        f"sudo rm -rf /home/{username_}/openvpn",
        f"sudo apt-get install git -y",
        f"sudo apt-get install wget -y",
        f"sudo apt --fix-broken install -y",

        f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/openvpn_installer.sh  -P /root/openvpn/",
        f"sudo chmod +x /root/openvpn/openvpn_installer.sh",

        f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/openvpn_installer.sh  -P /home/{username_}/openvpn/",
        f"sudo chmod +x /home/{username_}/openvpn/openvpn_installer.sh",

        f"sudo apt-get update -y",
        f"sudo apt-get install -y bridge-utils dmidecode iptables iproute2 libc6 libffi7 libgcc-s1 liblz4-1 liblzo2-2 libmariadb3 libpcap0.8 libssl1.1 libstdc++6 libsasl2-2 libsqlite3-0 net-tools python3-pkg-resources python3-migrate python3-sqlalchemy python3-mysqldb python3-ldap3 sqlite3 zlib1g python3-netaddr python3-arrow python3-lxml python3-constantly python3-hyperlink python3-automat python3-service-identity python3-cffi python3-defusedxml",
        f"sudo apt --fix-broken install -y",
        f"sudo apt --fix-broken install -y",
        f"sudo apt --fix-broken install -y",

        # ----------------------------------------------------------------------------node js pm2 iperf
        f"sudo apt-get install iperf",
        f"sudo curl -sL https://deb.nodesource.com/setup_17.x | sudo bash -",
        f"sudo apt-get install -y nodejs",
        f"sudo npm i -g npm",
        f"sudo apt install npm -y -o Dpkg::Options::=\"--force-confold\"",
        f"sudo npm i -g npm",
        f"sudo apt install npm -y",
        f"sudo npm i -g pm2",
        f"sudo pm2 delete all",
        f"sudo pm2 kill",
        f"sudo pm2 save",
        f"sudo pm2 startup",
        f"sudo pm2 save",
        f"sudo pm2 start \"iperf -s -p 1195\"",
        f"sudo pm2 save",
        f"sudo pm2 startup",
        # ----------------------------------------------------------------------------node js pm2 iperf
    ]
    for command_ in command_list:

        if type == "digitalocean" and ("upgrade -y" in command_):
            continue
        stdin, stdout, stderr = ssh.exec_command(command_)
        exit_status = stdout.channel.recv_exit_status()
        print(f"================> {command_}")
        for line in iter(stdout.readline, ""):
            if "Failed to fetch" in line:
                command_resolver = ["sudo apt clean",
                                    "sudo rm -rf /var/lib/apt/lists/*",
                                    "sudo mkdir -p /var/lib/apt/lists/partial",
                                    "sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32",
                                    "sudo apt-get update -y",
                                    'sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y',
                                    ]
                for command_resolve_ in command_resolver:
                    stdin, stdout, stderr = ssh.exec_command(command_resolve_)
                    exit_status = stdout.channel.recv_exit_status()
            print(line)

    # =================================================
    selected_ = select_(f"SELECT * FROM main_server_list WHERE id_key='{id_key_}'")
    selected_splash_vpn = select_(f"SELECT * FROM splash_vpn WHERE id_key='{id_key_}'")
    if enable_dns_custom and ((type == server_type_dns_custom or (
            len(selected_) > 0 and selected_[0]['type'] == server_type_dns_custom)) or (
                                      type == server_type_dns_custom or (
                                      len(selected_splash_vpn) > 0 and selected_splash_vpn[0][
                                  'type'] == server_type_dns_custom))):
        stdin, stdout, stderr = ssh.exec_command("sudo ufw allow out 53/tcp")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo ufw allow in 53/tcp")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo ufw allow out 53/udp")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo ufw allow in 53/udp")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("""iface=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}') && \
echo "Interface is: $iface" && \
sudo sysctl -w net.ipv4.ip_forward=1 && \
sudo sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf && \
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf && \
sudo iptables -t nat -A POSTROUTING -o $iface -j MASQUERADE && \
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections && \
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections && \
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent && \
sudo netfilter-persistent save""")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo ufw --force enable")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo iptables-save")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command("sudo ufw reload")
        exit_status = stdout.channel.recv_exit_status()

    chan = ssh.invoke_shell()
    chan.settimeout(0.0)
    chan.send('sudo -i\n')
    time.sleep(5)
    cmd = r'''
sudo tee /etc/apt/apt.conf.d/90noninteractive > /dev/null <<'EOF'
APT {
  Get {
    Assume-Yes "true";
    Quiet "2";
  };
};
DPkg {
  Options {
    "--force-confdef";
    "--force-confold";
  };
};
ENV {
  DEBIAN_FRONTEND "noninteractive";
  DEBIAN_PRIORITY "critical";
};
EOF

sudo tee /etc/needrestart/needrestart.conf > /dev/null <<'EOF'
# Auto‑restart all services without prompt
$nrconf{restart} = 'a';
# Ignore kernel‑upgrade hints entirely
$nrconf{kernelhints} = 'ignore';
# Run as daemon (no console output)
$nrconf{daemonize} = 1;
EOF
'''
    chan.send(cmd + "\n")
    time.sleep(5)

    if username_ != "root":
        chan.send(f'sudo bash /home/{username_}/openvpn/openvpn_installer.sh\n')
    else:
        chan.send('sudo bash /root/openvpn/openvpn_installer.sh\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('3\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\x7fy\n')
    log_channel(chan)
    time.sleep(5)

    time.sleep(30)

    chan.send('\x03')  # Ctrl+C
    time.sleep(1)
    output = chan.recv(1024).decode()
    print(output)

    chan.send('\x03')
    time.sleep(5)
    chan.send('\x03')
    log_channel(chan)
    time.sleep(5)

    # ------del
    if username_ != "root":
        chan.send(f'sudo bash /home/{username_}/openvpn/openvpn_installer.sh\n')
    else:
        chan.send('sudo bash /root/openvpn/openvpn_installer.sh\n')

    log_channel(chan)
    time.sleep(10)

    chan.send('\n')
    log_channel(chan)
    time.sleep(10)

    chan.send('\x7f')
    time.sleep(2)
    chan.send('n\n')
    # chan.send('y\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\n')
    log_channel(chan)
    time.sleep(10)

    chan.send('\x7f')
    time.sleep(2)
    chan.send('2\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\x7f')
    time.sleep(2)
    chan.send('\x7f')
    time.sleep(2)
    # -------------------------------------------
    selected_ = select_(f"SELECT * FROM main_server_list WHERE id_key='{id_key_}'")
    selected_splash_vpn = select_(f"SELECT * FROM splash_vpn WHERE id_key='{id_key_}'")
    if enable_dns_custom and ((type == server_type_dns_custom or (
            len(selected_) > 0 and selected_[0]['type'] == server_type_dns_custom)) or (
                                      type == server_type_dns_custom or (
                                      len(selected_splash_vpn) > 0 and selected_splash_vpn[0][
                                  'type'] == server_type_dns_custom))):
        chan.send('9\n')  # ---3 cloudflare -9 google
    else:
        chan.send('1\n')
    # -------------------------------------------
    log_channel(chan)
    time.sleep(5)

    chan.send('\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\n')
    log_channel(chan)
    time.sleep(5)

    time.sleep(60)

    chan.send('client\n')
    log_channel(chan)
    time.sleep(5)

    chan.send('\n')
    log_channel(chan)
    time.sleep(5)

    chan.send(
        "grep -q '^duplicate-cn' /etc/openvpn/server.conf || echo 'duplicate-cn' | sudo tee -a /etc/openvpn/server.conf\n")
    log_channel(chan)
    time.sleep(5)
    chan.send(
        'echo -e "\nmax-clients 2048\n" >> /etc/openvpn/server.conf\n')
    log_channel(chan)
    time.sleep(5)
    log_channel(chan)
    time.sleep(5)
    chan.send("sudo systemctl restart openvpn@server\n")
    log_channel(chan)
    time.sleep(5)

    if install_socks5_proxy and splash_vpn == "yes":
        chan.send("sudo dpkg --remove dante-server\n")
        log_channel(chan)
        time.sleep(5)
        chan.send("sudo wget https://raw.githubusercontent.com/saaiful/socks5/main/socks5.sh\n")
        log_channel(chan)
        time.sleep(5)
        chan.send("sudo chmod 777 *\n")
        log_channel(chan)
        time.sleep(2)
        chan.send("sudo bash socks5.sh\n")
        log_channel(chan)
        time.sleep(2)
        chan.send(f"{out_traffic_socks5_port}\n")
        log_channel(chan)
        time.sleep(60)
        chan.send("emadxd\n")
        log_channel(chan)
        time.sleep(2)
        chan.send("emadxd\n")
        log_channel(chan)
        time.sleep(2)

    # -----------------------------------------------------------------disconnect and reload
    if splash_vpn == "yes":
        command_list_reload_disconnect = [
            # f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/splash_vpn_openvpn_disconnect.py  -P /root/openvpn/",
            # f"sudo chmod 777 /root/openvpn/splash_vpn_openvpn_disconnect.py",

            # f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/splash_vpn_openvpn_disconnect.py  -P /home/{username_}/openvpn/",
            # f"sudo chmod 777 /home/{username_}/openvpn/splash_vpn_openvpn_disconnect.py",
            # ----
            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/reboot_splash_vpn.py  -P /root/openvpn/",
            f"sudo chmod 777 /root/openvpn/reboot_splash_vpn.py",

            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/reboot_splash_vpn.py  -P /home/{username_}/openvpn/",
            f"sudo chmod 777 /home/{username_}/openvpn/reboot_splash_vpn.py",
            # -----
        ]

        if username_ != "root":
            command_list_reload_disconnect.extend([
                # f"sudo pm2 start \"python3 /home/{username_}/openvpn/splash_vpn_openvpn_disconnect.py\"",
                f"sudo pm2 start \"python3 /home/{username_}/openvpn/reboot_splash_vpn.py\"",
                f"sudo pm2 save",
                f"sudo pm2 startup",
                f"sudo pm2 save",
            ])
        else:
            command_list_reload_disconnect.extend([
                # f"sudo pm2 start \"python3 /root/openvpn/splash_vpn_openvpn_disconnect.py\"",
                f"sudo pm2 start \"python3 /root/openvpn/reboot_splash_vpn.py\"",
                f"sudo pm2 save",
                f"sudo pm2 startup",
                f"sudo pm2 save",
            ])
    else:
        command_list_reload_disconnect = [
            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/reboot.py  -P /root/openvpn/",
            f"sudo chmod 777 /root/openvpn/reboot.py",

            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/reboot.py  -P /home/{username_}/openvpn/",
            f"sudo chmod 777 /home/{username_}/openvpn/reboot.py",
        ]
        if username_ != "root":
            command_list_reload_disconnect.extend([
                f"sudo pm2 start \"python3 /home/{username_}/openvpn/reboot.py\"",
                f"sudo pm2 save",
                f"sudo pm2 startup",
                f"sudo pm2 save",
            ])
        else:
            command_list_reload_disconnect.extend([
                f"sudo pm2 start \"python3 /root/openvpn/reboot.py\"",
                f"sudo pm2 save",
                f"sudo pm2 startup",
                f"sudo pm2 save",
            ])

    for command_ in command_list_reload_disconnect:
        stdin, stdout, stderr = ssh.exec_command(command_)
        exit_status = stdout.channel.recv_exit_status()
        print(f"================> {command_}")
        for line in iter(stdout.readline, ""):
            print(line)

    # -----------------------------------------------------------------disconnect and reload

    # -------------------v2ray installer
    global force_create_v2ray
    if force_create_v2ray:
        chan.send("sudo -i\n")
        log_channel(chan)
        time.sleep(5)
        chan.send("yes | sudo v2ray uninstall\n")
        log_channel(chan)
        time.sleep(5)
        chan.send("bash <(sudo curl -s -L https://git.io/v2ray.sh)\n")
        log_channel(chan)
        time.sleep(30)
        chan.send("sudo rm -rf /etc/v2ray/conf/*\n")
        log_channel(chan)
        time.sleep(5)
        global v2ray_config
        v2ray_config = f"{v2ray_config}".replace("xxx.ip", ip_)
        chan.send(f"sudo echo '{v2ray_config}' > /etc/v2ray/conf/xd.json\n")
        log_channel(chan)
        time.sleep(5)
        chan.send("sudo v2ray restart\n")
        res_v2ray = log_channel(chan)
        if "command not found" in res_v2ray:
            send_message_telegram(f"❌ ERROR (V2ray) {ip_}", chat_id_)
            ssh.exec_command("sudo /sbin/reboot -f > /dev/null 2>&1 &")
            return False
        time.sleep(5)
        try:
            chan.close()
        except:
            print("close except")
    # =================================================
    psk_ = create_psk_secret()

    content = f"""[openvpn]
accept = 443
connect = 127.0.0.1:1194
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
[smtp587]
accept = 587
connect = 127.0.0.1:1194
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
[smtp25]
accept = 25
connect = 127.0.0.1:1194
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem"""
    if username_ == "root":
        dir_save_ = "/root"
    else:
        dir_save_ = f"/home/{username_}"

    # ---------------
    # stdin, stdout, stderr = ssh.exec_command("""lscpu | grep "Core(s) per socket" | awk '{print $NF}'""")
    stdin, stdout, stderr = ssh.exec_command("""lscpu | grep '^CPU(s):' | awk '{print $2}'""")
    exit_status = stdout.channel.recv_exit_status()
    cpu_set_ = "8"
    for line in iter(stdout.readline, ""):
        cpu_set_ = line
        # if int(cpu_set_) >= 2:
        #    cpu_set_ = int(cpu_set_) / 2
    # ---------------
    # --------------test emadxd clouvider
    try:
        selected_ = select_(f"SELECT * FROM main_server_list WHERE id_key='{id_key_}'")
        if type == 'clouvider' or (len(selected_) > 0 and selected_[0]['type'] == "clouvider"):
            cpu_set_ = round(float(f"{cpu_set_}") / 2)
    except:
        print("-")

    # --------------test emadxd clouvider
    print(cpu_set_)
    command_list = [
        f'sudo /usr/local/openvpn_as/scripts/sacli --user openvpn --key "prop_autologin" --value "true" UserPropPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --user openvpn --key "prop_autologin" --value "true" UserPropPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "auth.module.type" --value "pam" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.enable" --value "true" ConfigPut',
        # f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.daemon.0.listen.protocol" --value "tcp" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.port_share.enable" --value "true" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.tls_cc_security" --value "none" ConfigPut',
        # f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.max_clients" --value "16384" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.max_clients" --value "262144" ConfigPut',

        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.daemon.0.client.network" --value "172.16.0.0" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.daemon.0.client.netmask_bits" --value "16" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.group_pool.0" --value "172.16.0.0/16" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.tcp.n_daemons" --value "{cpu_set_}" ConfigPut',
        f'sudo /usr/local/openvpn_as/scripts/sacli --key "vpn.server.daemon.udp.n_daemons" --value "0" ConfigPut',

        f'sudo /usr/local/openvpn_as/scripts/sacli --user "openvpn" --new_pass=*141*11#eEe SetLocalPassword',
        f'sudo /usr/local/openvpn_as/scripts/sacli start',
        f'sudo /usr/local/openvpn_as/scripts/sacli start',
        f'sudo apt-get update -y',

        # ------------------------------------------------------------
        "sudo apt-get install ufw",
        # "sudo ufw default deny incoming",
        # "sudo ufw default allow outgoing",

        # "sudo ufw allow 22",
        # "sudo ufw allow 443",
        # # "sudo ufw allow 3128",
        # "sudo ufw allow 80",
        # "sudo ufw allow 6969",
        # "sudo ufw allow 1194",
        # "sudo ufw allow 1195",
        # "sudo ufw allow 8080",
        #
        # "sudo ufw deny out 25",
        # "sudo ufw deny in 25",
        # "sudo ufw deny out 587",
        # "sudo ufw deny in 587",
        # "sudo ufw deny out 465",
        # "sudo ufw deny in 465",
        # "sudo ufw deny out 2525",
        # "sudo ufw deny in 2525",
        #
        # "sudo ufw allow out 53/tcp",
        # "sudo ufw allow in 53/tcp",
        # "sudo ufw allow out 53/udp",
        # "sudo ufw allow in 53/udp",
        #
        # "sudo ufw --force enable",
        # "sudo iptables-save",
        # "iptables-save",
        # "sudo ufw reload",
        "sudo ufw default deny incoming",
        "sudo ufw default deny outgoing",
        "sudo ufw allow in 22",
        "sudo ufw allow in 443",
        "sudo ufw allow in 80",
        "sudo ufw allow in 6969",
        "sudo ufw allow in 1194",
        "sudo ufw allow in 1195",
        "sudo ufw allow in 8080",
        "sudo ufw allow in 8443",
        "sudo ufw allow in 3128",
        "sudo ufw allow in 53",
        "sudo ufw allow in 2083",
        "sudo ufw allow in 2082",
        f"sudo ufw allow in {out_traffic_socks5_port}",

        "sudo ufw allow out 22",
        "sudo ufw allow out 443",
        "sudo ufw allow out 80",
        "sudo ufw allow out 6969",
        "sudo ufw allow out 1194",
        "sudo ufw allow out 1195",
        "sudo ufw allow out 8080",
        "sudo ufw allow out 8443",
        "sudo ufw allow out 3128",
        "sudo ufw allow out 53",
        "sudo ufw allow out 2083",
        "sudo ufw allow out 2082",
        f"sudo ufw allow out {out_traffic_socks5_port}",

        "sudo ufw allow out 12345",
        "sudo ufw allow in 12345",

        "sudo ufw --force enable",
        "sudo iptables-save",
        "iptables-save",
        "sudo ufw reload",
        # ------------------------------------------------------------
        # "yes | sudo v2ray uninstall",
        # "bash <(sudo curl -s -L https://git.io/v2ray.sh)",
        # # "sudo v2ray port tcp 1195",
        #
        # f"sudo rm -rf /etc/v2ray/conf/*",
        # f"sudo echo '{v2ray_config}' > /etc/v2ray/conf/xd.json",
        # "sudo v2ray restart",

        # f'sudo rm -rf /root/openvpn',
        # f'sudo rm -rf /home/{username_}/openvpn',
        # ----------------------------------------------------
        f"sudo squid-uninstall -y",
        f"sudo apt-get purge --auto-remove squid -y",
        # f"""sudo apt-get install -y squid apache2-utils && sudo htpasswd -bc /etc/squid/passwords emadxd 1 && sudo sed -i 's/^http_port .*/http_port 2083/' /etc/squid/squid.conf && sudo bash -c 'echo -e "\n# Authentication settings\nauth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd\nauth_param basic realm proxy\nacl authenticated proxy_auth REQUIRED\nhttp_access allow authenticated" >> /etc/squid/squid.conf' && sudo systemctl restart squid""",
        f"sudo wget https://raw.githubusercontent.com/serverok/squid-proxy-installer/master/squid3-install.sh -O squid3-install.sh",
        f"sudo bash squid3-install.sh",
        f"sudo /usr/bin/htpasswd -b -c /etc/squid/passwd emadxd emadxd",
        f"sudo systemctl reload squid",

        f"sudo sed -i 's/http_port 3128/http_port 2083/' /etc/squid/squid.conf",
        f"sudo systemctl reload squid",
        f"sudo service squid restart",
        "sudo ufw allow out 3128",
        "sudo ufw allow in 3128",
        "sudo ufw allow in 2083",
        "sudo ufw allow in 2083",
        "sudo ufw reload",
        # ----------------------------------------------------
    ]
    for command_ in command_list:
        stdin, stdout, stderr = ssh.exec_command(command_)
        exit_status = stdout.channel.recv_exit_status()
        print(f"================> {command_}")
        for line in iter(stdout.readline, ""):
            print(line)
    # =================================================
    try:
        sftp_client = ssh.open_sftp()
        if username_ != "root":
            stdin, stdout, stderr = ssh.exec_command(f"sudo cp -r /root/client.ovpn /home/{username_}/client.ovpn")
            exit_status = stdout.channel.recv_exit_status()  # Blocking call
            time.sleep(2)
            remote_file = sftp_client.open(f'/home/{username_}/client.ovpn')
        else:
            remote_file = sftp_client.open('/root/client.ovpn')
        # ----
        content_ovpn = ""
        try:
            for line in remote_file:
                content_ovpn += line
        finally:
            remote_file.close()

        content_ovpn = content_ovpn.replace("sudo export APPROVE_IP=y", "")
        content_ovpn = content_ovpn.replace("export APPROVE_IP=y", "")
        content_ovpn = content_ovpn.replace("APPROVE_IP=y", "")
        if len(content_ovpn) < 1000:
            send_message_telegram(f"❌1 ERROR {ip_}", chat_id_)
            return False
    except Exception as e:
        send_message_telegram(f"❌2 ERROR {ip_} {e}", chat_id_)
        return False

    content_ovpn = strip_comments(content_ovpn)
    pattern_ip = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    content_ovpn = re.sub(pattern_ip, "127.0.0.1", content_ovpn)
    content_ovpn = content_ovpn.replace(f"1194", "8585")
    # -------------------------------------------------- beta
    command_list = []
    global firewall_ip_list_deny_out
    global ip_rout_dont_use_vpn_client
    global ip_rout_dont_use_vpn_server
    for ufw_ip_subnet in firewall_ip_list_deny_out:
        command_list.append(f"ufw deny out from any to {ufw_ip_subnet}")
        ip_rout_dont_use_vpn_server.append(convert_to_net_gateway(f"{ufw_ip_subnet}"))

    command_list.extend([
        f"sudo ufw --force enable",
        f"sudo ufw reload",
        f"sudo ufw --force enable",
    ])
    # ---------------------
    # stdin, stdout, stderr = ssh.exec_command(
    #     f"""sudo sed -i -e 's/^push "redirect-gateway def1"/push "redirect-gateway def1 bypass-dhcp"/' /etc/openvpn/server.conf""")
    # exit_status = stdout.channel.recv_exit_status()

    # stdin, stdout, stderr = ssh.exec_command(
    #     f'sudo systemctl restart openvpn@server')
    # exit_status = stdout.channel.recv_exit_status()

    selected_ = select_(f"SELECT * FROM main_server_list WHERE id_key='{id_key_}'")
    selected_splash_vpn = select_(f"SELECT * FROM splash_vpn WHERE id_key='{id_key_}'")

    if enable_anti_synflood_ovh and ((type == 'ovh' or (len(selected_) > 0 and selected_[0]['type'] == "ovh")) or (
            type == 'ovh' or (len(selected_splash_vpn) > 0 and selected_splash_vpn[0]['type'] == "ovh"))):
        stdin, stdout, stderr = ssh.exec_command(
            """sudo DEBIAN_FRONTEND=noninteractive apt install iptables-persistent -y""")
        exit_status = stdout.channel.recv_exit_status()
        # ----
        stdin, stdout, stderr = ssh.exec_command(f"""sudo crontab -l | grep -v 'iptables -I FORWARD' | crontab -""")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command(
            f"""sudo crontab -l -u {username_} | grep -v 'iptables -I FORWARD' | sudo crontab -u {username_} -""")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr = ssh.exec_command(
            f"""sudo crontab -l -u root | grep -v '10.8.0.0/14' | sudo crontab -u root -""")
        exit_status = stdout.channel.recv_exit_status()
        stdin, stdout, stderr = ssh.exec_command(
            f"""sudo crontab -l -u ubuntu | grep -v '10.8.0.0/14' | sudo crontab -u ubuntu -""")
        exit_status = stdout.channel.recv_exit_status()
        max_syn_flood_1_user = 50

        stdin, stdout, stderr = ssh.exec_command(
            f"""(sudo crontab -l -u root 2>/dev/null; echo '@reboot iptables -C FORWARD -p tcp --syn -s 10.8.0.0/14 -m connlimit --connlimit-above {max_syn_flood_1_user} --connlimit-mask 32 -j LOG --log-prefix "CONNLIMIT_DROP: " 2>/dev/null || iptables -I FORWARD 1 -p tcp --syn -s 10.8.0.0/14 -m connlimit --connlimit-above {max_syn_flood_1_user} --connlimit-mask 32 -j LOG --log-prefix "CONNLIMIT_DROP: "'; echo '@reboot iptables -C FORWARD -p tcp --syn -s 10.8.0.0/14 -m connlimit --connlimit-above {max_syn_flood_1_user} --connlimit-mask 32 -j DROP 2>/dev/null || iptables -I FORWARD 2 -p tcp --syn -s 10.8.0.0/14 -m connlimit --connlimit-above {max_syn_flood_1_user} --connlimit-mask 32 -j DROP') | sudo crontab -u root -"""
        )

        exit_status = stdout.channel.recv_exit_status()
    # ---------------------
    if create_out_traffic_ads_socks5 and splash_vpn != "yes":
        # -----
        if use_redsocks:
            stdin, stdout, stderr = ssh.exec_command("sudo apt-get install redsocks -y")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(20)
            stdin, stdout, stderr = ssh.exec_command(
                "sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/xd_red.conf -O /etc/redsocks.conf")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(5)

            stdin, stdout, stderr = ssh.exec_command(
                f"sudo sed -i 's/XD_IP/{out_traffic_socks5_ip}/g; s/XD_PORT/{out_traffic_socks5_port}/g' /etc/redsocks.conf")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(2)
            stdin, stdout, stderr = ssh.exec_command("sudo systemctl restart redsocks")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(2)
            stdin, stdout, stderr = ssh.exec_command("sudo apt-get install build-essential -y")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(2)
            stdin, stdout, stderr = ssh.exec_command("sudo apt-get install libevent-dev -y")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(2)
            stdin, stdout, stderr = ssh.exec_command("sudo systemctl restart redsocks")
            exit_status = stdout.channel.recv_exit_status()
            time.sleep(2)
            stdin, stdout, stderr = ssh.exec_command("sudo systemctl enable redsocks")
            exit_status = stdout.channel.recv_exit_status()

        # time.sleep(2)
        # stdin, stdout, stderr = ssh.exec_command("sudo apt install -y ipset iproute2 dnsutils")
        # exit_status = stdout.channel.recv_exit_status()

        time.sleep(20)
        stdin, stdout, stderr = ssh.exec_command(
            "sudo ufw disable")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(5)
        stdin, stdout, stderr = ssh.exec_command(
            "sudo systemctl disable ufw")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(5)

        file_limit_increase = "xd_limit_new.py"

        stdin, stdout, stderr = ssh.exec_command(
            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/{file_limit_increase}  -P /root/openvpn/")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(5)
        stdin, stdout, stderr = ssh.exec_command(f"sudo chmod 777 /root/openvpn/{file_limit_increase}")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(f'sudo pm2 start "python3 /root/openvpn/{file_limit_increase}"')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        # stdin, stdout, stderr = ssh.exec_command(f'sudo apt-get install dnsmasq -y')
        # exit_status = stdout.channel.recv_exit_status()
        # time.sleep(2)
        # stdin, stdout, stderr = ssh.exec_command(f'sudo apt-get install ipset -y')
        # exit_status = stdout.channel.recv_exit_status()
        # time.sleep(2)
        time.sleep(30)

        stdin, stdout, stderr = ssh.exec_command(
            f"sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/master/{route_ads}  -P /root/openvpn/")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(5)
        stdin, stdout, stderr = ssh.exec_command(f"sudo chmod 777 /root/openvpn/{route_ads}")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(
            f'sudo pm2 start "python3 /root/openvpn/{route_ads}"')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(60)

        # command_shadowsocks_client = f'sudo pm2 start "sudo ss-local -s {out_traffic_socks5_ip} -p 8388 -l {out_traffic_socks5_port} -k emadxd -m aes-256-gcm" --max-restarts 10000 --restart-delay 5000'
        # if use_udp_shadowsocks:
        #    command_shadowsocks_client = command_shadowsocks_client.replace("aes-256-gcm", "aes-256-gcm -u")
        # stdin, stdout, stderr = ssh.exec_command(command_shadowsocks_client)
        # exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr = ssh.exec_command("sudo rm -rf /root/openvpn/start_ss.sh")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(
            "sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/start_ss.sh -P /root/openvpn/")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command("sudo chmod 777 /root/openvpn/start_ss.sh")
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(
            'sudo pm2 start "/root/openvpn/start_ss.sh" --max-restarts 10000 --restart-delay 5000')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)

        stdin, stdout, stderr = ssh.exec_command(f'sudo pm2 save')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(f'sudo pm2 startup')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command(f'sudo pm2 save')
        exit_status = stdout.channel.recv_exit_status()
        time.sleep(2)
    # ---------------------

    if (type == 'hetzner' or (len(selected_) > 0 and selected_[0]['type'] == "hetzner")):
        for command_ in command_list:
            stdin, stdout, stderr = ssh.exec_command(command_)
            exit_status = stdout.channel.recv_exit_status()
            print(f"================> {command_}")
            for line in iter(stdout.readline, ""):
                print(line)
        # -----------------------------------------------------
        route_server_side = ""
        route_client_side = ""
        for route_ in ip_rout_dont_use_vpn_server:
            route_server_side += f"""push "route {route_} net_gateway"\n"""
        for route_ in ip_rout_dont_use_vpn_client:
            route_client_side += f"route {convert_to_net_gateway(route_)} net_gateway\n"

        stdin, stdout, stderr = ssh.exec_command(
            f"sudo echo '{route_server_side}' >> /etc/openvpn/server.conf")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr = ssh.exec_command(
            f"sudo echo '{route_client_side}' >> /etc/openvpn/server.conf")
        exit_status = stdout.channel.recv_exit_status()

        stdin, stdout, stderr = ssh.exec_command(
            f'sudo systemctl restart openvpn@server')
        exit_status = stdout.channel.recv_exit_status()
        # -----------------------------------------------------

        content_ovpn = f"""script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
route {ip_} 255.255.255.255 net_gateway\n{route_client_side}\n{content_ovpn}"""
    else:
        content_ovpn = f"""script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
route {ip_} 255.255.255.255 net_gateway\n{content_ovpn}"""
    # -------------------------------------------------- beta
    content_ovpn = content_ovpn.replace("udp", "tcp")
    # ----------------------------------------------------
    content_rayvpn = """{
"add":"xd.com",
"aid":"0",
"alpn":"",
"fp":"",
"host":"",
"id":"6515d80a-a2ae-4703-85b9-a70760fc9a21",
"net":"tcp",
"path":"",
"port":"8080",
"ps":"xd",
"scy":"auto",
"sni":"",
"tls":"",
"type":"none",
"v":"2"
}"""
    global use_ipv6
    ipv6_ = ip_
    if use_ipv6:
        if type == 'ovh':
            stdin, stdout, stderr = ssh.exec_command(
                "ip -6 addr show dev ens3 | grep -oP '(?<=inet6 ).*?(?=/)' | grep -v '^fe80:' | head -n 1")
        else:
            stdin, stdout, stderr = ssh.exec_command(
                "ip -6 addr show dev eth0 | grep -oP '(?<=inet6 ).*?(?=/)' | grep -v '^fe80:' | head -n 1")

        ipv6_ = f"{stdout.read().decode('utf-8')}".replace("\n", "").replace(" ", "")
        if not is_valid_ipv6(ipv6_):
            ipv6_ = ip_
            use_ipv6 = False

    global namecheap_auto
    if namecheap_auto:  # and tunnel_api_key_ == 'v2ray':
        selected_domain_list_ = select_(f"SELECT * FROM domain_list ORDER BY RAND() LIMIT 1")
        target_domain_ = selected_domain_list_[0]['domain']
        target_zone_id_ = selected_domain_list_[0]['zone_id']
        new_ipv6_addresses = []
        if use_ipv6:
            for i in range(1):
                ipv6_temp_ = ipv6_.split("::")[0] + f":{generate_random_ipv6()}"
                ipv6_temp_ = f"{ipv6_temp_}::1"
                new_ipv6_addresses.append(f"{ipv6_temp_}/64")
                res___ = add_custom_dns_ipv6_cloudflare_erfanghasemi1397(ip_, ipv6_temp_, target_domain_,
                                                                         target_zone_id_)

            # -----------------
            stdin, stdout, stderr = ssh.exec_command(f'sudo cat /etc/netplan/*.yaml')
            config_text = stdout.read().decode('utf-8')
            config = yaml.safe_load(config_text)
            if 'ethernets' in config['network'] and 'eth0' in config['network']['ethernets']:
                config['network']['ethernets']['eth0']['addresses'] += new_ipv6_addresses

            if 'ethernets' in config['network'] and 'ens3' in config['network']['ethernets']:
                config['network']['ethernets']['ens3']['addresses'] += new_ipv6_addresses

            config_text = yaml.dump(config, default_flow_style=False)
            print(config_text)
            stdin, stdout, stderr = ssh.exec_command(f'sudo echo "{config_text}" | sudo tee /etc/netplan/*.yaml')
            exit_status = stdout.channel.recv_exit_status()
            stdin, stdout, stderr = ssh.exec_command(f'sudo netplan apply')
            exit_status = stdout.channel.recv_exit_status()
            # -----------------
        else:
            # res___ = add_custom_dns_cloudflare_erfanghasemi1397(ip_, target_domain_, target_zone_id_)
            res___ = add_dns_cloudflare(ip_, 999999, True)
        print(res___)
        if res___['result'] == 'success':
            content_rayvpn = content_rayvpn.replace("xd.com", f"{res___['body']}.")
            content_rayvpn = f"vmess://{base64_encode_(content_rayvpn)}"
        else:
            content_rayvpn = "null"
    else:
        content_rayvpn = content_rayvpn.replace("xd.com", f"{ip_}")
        content_rayvpn = f"vmess://{base64_encode_(content_rayvpn)}"
    # ----------------------------------------------------
    selected_ = select_(f"SELECT * FROM main_server_list WHERE id_key='{id_key_}'")
    if len(selected_) <= 0:
        if tunnel_api_key_ == 'backup':
            insert_(
                f"INSERT INTO main_server_list(`config`,`ray_config`, `ip`, `username`, `password`, `tunnel_api_key`, `max_tunnel`, `package`, `account_id`, `id_key`, `type`, `isp`, `sni`, `domain_cloudflare`) VALUES ('{content_ovpn}','{content_rayvpn}', '{ip_}', '{username_}', '{passwd_}', '{tunnel_api_key_}', '0', '{package_}', '{account_id_}','{id_key_}','{type}','{isp}','{sni}','{domain_cloudflare}')")
        else:
            insert_(
                f"INSERT INTO main_server_list(`config`,`ray_config`, `ip`, `username`, `password`, `tunnel_api_key`, `package`, `account_id`, `id_key`, `type`, `isp`, `sni`, `domain_cloudflare`) VALUES ('{content_ovpn}','{content_rayvpn}', '{ip_}', '{username_}', '{passwd_}', '{tunnel_api_key_}', '{package_}', '{account_id_}','{id_key_}','{type}','{isp}','{sni}','{domain_cloudflare}')")

    else:
        if passwd_ != 'null':
            update_(
                f"UPDATE main_server_list SET config='{content_ovpn}', ray_config='{content_rayvpn}', password='*141*11#eEe' WHERE ip='{ip_}'")
        else:
            update_(
                f"UPDATE main_server_list SET config='{content_ovpn}', ray_config='{content_rayvpn}' WHERE ip='{ip_}'")

    print("Finish ip: " + ip_)
    time.sleep(2)
    send_message_telegram(f"✅ Finish: https://{ip_}:6969/admin\n{content_rayvpn}", chat_id_)
    # ssh.exec_command("sudo /sbin/reboot -f > /dev/null 2>&1 &")
    ssh.exec_command("sudo /sbin/reboot")
    return True


def is_valid_ipv6(Ip):
    ipv6 = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    if re.search(ipv6, Ip):
        return True
    return False


def base64_encode_(str):
    return (base64.b64encode(str.encode('utf-8'))).decode("utf-8")


def base64_decode_(str):
    return base64.b64decode(str).decode('utf-8')


def remove_color_codes(input_text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', input_text)


def get_vmess_config_from_string(text_):
    text_ = remove_color_codes(text_)
    for msg_split in text_.split("\n"):
        if re.match(r"^vmess://(.*)\s?", msg_split):
            result_ = re.search(r"^vmess://(.*)\s?", msg_split)
            return f"vmess://{result_.group(1)}"


def generate_random_ipv6():
    random_hex = ''.join(random.choice('0123456789abcdef') for _ in range(4))
    return random_hex


def add_custom_dns_cloudflare_erfanghasemi1397(ip_, domain_, zone_id):
    select___ = select_(f"SELECT * FROM domain_list WHERE `domain`='{domain_}'")
    if len(select___) <= 0:
        return {"result": "error", "body": f'dont allow now'}

    API_KEY_CLOUDFLARE = f"{select___[0]['api_key']}"
    headers = {"Authorization": f"Bearer {API_KEY_CLOUDFLARE}"}
    # Set the DNS record details

    data = {
        "type": "A",
        "name": f'7cdn{ip_.replace(".", "")}',
        "content": ip_,
        # "ttl": 1,
        "proxied": False
    }
    response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers,
                             json=data)
    if response.status_code == 200:
        print("DNS record created successfully!")
        return {"result": "success", "body": f'7cdn{ip_.replace(".", "")}.{domain_}'}
    else:
        print("Failed to create DNS record. Status code:", response.status_code)
        res_json_ = response.json()
        if res_json_['errors'][0]['message'] == "Record already exists.":
            return {"result": "success", "body": f'7cdn{ip_.replace(".", "")}.{domain_}'}

        return {"result": "error", "body": f'{response.text}'}


def generate_random_chinese_word(length):
    chinese_characters = ["你", "好", "我", "是", "学", "生", "中", "国", "语", "文", "随", "机", "字"]

    if length <= 0:
        return ""

    random_word = ''.join(random.choice(chinese_characters) for _ in range(length))
    return random_word


def add_custom_dns_ipv6_cloudflare_erfanghasemi1397(ip_, ipv6_, domain_, zone_id):
    headers = {"Authorization": "Bearer 83Q7ViNCkIvx_PXZ8qWH8VeY_gaZXO7oFDgU9PMT"}
    headers = {"Authorization": "Bearer XV5aYTEdTAwz0kpVBKGmBkbjWn_i-mw2Y8OWEWBt"}
    # Set the DNS record details
    sub_ = generate_random_chinese_word(5)
    sub_ = f'7cdn{ip_.replace(".", "").replace(":", "").replace("/", "")}'
    data = {
        "type": "AAAA",
        "name": f'{sub_}',
        "content": ipv6_,
        "proxied": False
    }
    response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers,
                             json=data)
    if response.status_code == 200:
        print("DNS record created successfully!")
        return {"result": "success", "body": f'{sub_}.{domain_}'}
    else:
        print("Failed to create DNS record. Status code:", response.status_code)
        res_json_ = response.json()
        if res_json_['errors'][0]['message'] == "Record already exists.":
            return {"result": "success", "body": f'{sub_}.{domain_}'}

        return {"result": "error", "body": f'{response.text}'}


# ------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    splash_vpn = "no"
    try:
        splash_vpn = sys.argv[9]
    except:
        print("have not id static")

    install_script(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7],
                   sys.argv[8], splash_vpn)
