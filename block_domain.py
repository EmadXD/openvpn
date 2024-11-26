# wget --backups=1 https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/block_domain.py -P /root/ && chmod 777 * && pm2 start "python3.8 block_domain.py" && pm2 save && pm2 startup && pm2 save


import os
import time

while True:
    os.system("sudo apt update -y")
    os.system("sudo apt install whois -y")
    os.system("sudo rm -rf /root/block_domain.sh")
    os.system("sudo wget --backups=1 https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/block_domain.sh  -P /root/")
    os.system("sudo chmod 777 /root/block_domain.sh")
    # os.system("""sudo sed -i 's/\r$//' /root/block_domain.sh""")
    os.system("sudo /root/block_domain.sh facebook.com add")
    os.system("sudo /root/block_domain.sh instagram.com add")
    os.system("sudo /root/block_domain.sh fbcdn.com add")
    os.system("sudo /root/block_domain.sh fbcdn.net add")

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
