#!/bin/bash
# دریافت IP از DNS
IP=$(dig +short socks_main.aparatvpn.com | head -n 1)

echo "[$(date)] Starting ss-local with server IP: $IP"

# اجرای ss-local
exec ss-local -s "$IP" -p 8388 -l 1080 -k "emadxd" -m "aes-256-gcm" -u
