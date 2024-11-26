import os
import time

while True:
    os.system("sudo wget https://raw.githubusercontent.com/EmadXD/openvpn/refs/heads/main/block_domain  -P /root/")
    os.system("sudo chmod 777 /root/block_domain")
    os.system("""sudo sed -i 's/\r$//' /root/block_domain""")
    os.system("sudo sh /root/block_domain facebook.com add")
    os.system("sudo sh /root/block_domain instagram.com add")
    os.system("sudo sh /root/block_domain fbcdn.com add")
    os.system("sudo sh /root/block_domain fbcdn.net add")

    # -------------telegram
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.4.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.8.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.16.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.12.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 149.154.160.0/20 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.105.192.0/23 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 91.108.20.0/22 -j DROP")
    os.system("/sbin/iptables -I FORWARD 1 -i as+ -d 185.76.151.0/24 -j DROP")
    time.sleep(600)  # --10 minutes
