# Pre-Authentication Persistent Denial of Service in Edimax BR-6208AC V2 Web Server (Double-401 uClibc free() Heap Over-Read)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The web management server (`/bin/webs`, a GoAhead-derived Boa/0.94.14rc21 running as root) of the
Edimax BR-6208AC V2 (firmware 1.03) **crashes on any request that carries invalid HTTP Basic
credentials** to an authentication-protected page (e.g. `/index.asp`). The firmware contains no
watchdog or respawn mechanism, so a **single unauthenticated HTTP request permanently disables the
entire management interface** until the device is power-cycled.

## Affected Product

- Vendor: Edimax
- Product: BR-6208AC V2 (hardware version 2.0)
- Firmware: 1.03 — the latest publicly available version for this model. Edimax has publicly
  declared this product End-of-Life: no further firmware updates will be released.

## Vulnerability Details

- Type: CWE-125 (Out-of-bounds Read) leading to unrecoverable denial of service
- Root cause:
  1. Edimax modified the stock Boa 401 path so that `send_r_unauthorized()` is invoked **twice**
     for failed Basic authentication. The 401 responses also disclose the realm string
     `Default:admin/1234`, leaking the factory default credentials.
  2. During connection teardown the server calls `free()` on a request buffer
     (`free(req->0x110)`, call site webs @ 0x40e2a8).
  3. The bundled uClibc `free()` (libc @ 0x49c4c) reads the *next* chunk header **before**
     checking whether the chunk borders the heap top. When the freed chunk ends exactly at the
     program break — the steady state after processing a 401 — it reads past `brk` into an
     unmapped page and the process dies with SIGSEGV.

  Crash signature (two independent runs, qemu-user `-strace`):

  | run | si_addr | brk at crash | freed chunk | chunk size | chunk end |
  |-----|---------|--------------|-------------|------------|-----------|
  | E1  | 0x532004 | 0x532000 | 0x52fc70 | 0x2390 | 0x532000 (= brk) |
  | E5  | 0x52e004 | 0x52e000 | 0x52b1a0 | 0x2e60 | 0x52e000 (= brk) |

  Both runs satisfy "chunk end == brk", making the over-read **deterministic**, not a
  probabilistic heap-corruption artifact.

## Proof of Concept (non-destructive)

Against a live device at 192.168.2.1:

```bash
# 1. Send any invalid Basic credential to an authentication-protected page
curl -v -u admin:wrongpass http://192.168.2.1/index.asp
# Expected: HTTP 401 (sent twice, realm discloses "Default:admin/1234")

# 2. Immediately afterwards, the web server is gone
curl -v http://192.168.2.1/
# Expected: connection refused — persistent until power-cycle
```

Observed in a rehosted firmware environment (docker + qemu-mipsel, firmware 1.03 rootfs):

```
GET /index.asp (bad credentials)  -> 401
--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=0x00532004} ---   # read 4 bytes past brk
webs process count: 0   (no watchdog/respawn in inittab, init.d or crontab)
```

Trigger-matrix (12 independent runs, fresh server each time): **every request that reaches the
" credentials-present-but-invalid → double 401" path crashes the server (8/8)** — short
credentials, passwords up to 1000 chars, empty username, empty password, Unicode, shell
metacharacters. Control cases do **not** crash: valid credentials (HTTP 200), no credentials
(single 401), requests rejected with 400 before authentication (over-long username, malformed
base64), and the unauthenticated `/` redirect (302).

Recovery: power-cycle the device. No configuration is modified by the PoC.

## Impact

- Attacker: unauthenticated network client (LAN/Wi-Fi side by default; WAN side if remote
  management is enabled).
- Effect: permanent loss of the web management interface (and of the goform API it hosts) with a
  single request. Repeated play after every reboot keeps the device permanently unmanageable.
- Amplifier: the disclosed realm `Default:admin/1234` advertises the factory credentials;
  devices still running them are fully manageable by anyone — this crash can equally be used to
  *blind* administrators during/after an intrusion.

## CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 (High)**
Unauthenticated, single-request, deterministic persistent DoS of the device's only management
plane. (If scored LAN-side only: AV:A = 6.5.)

## Discovery

Discovered by Zimo-666 on 2026-10-12 via firmware rehosting (qemu-user), crash forensics and
static root-cause analysis of the bundled uClibc. Vendor notified: see top-level README.
