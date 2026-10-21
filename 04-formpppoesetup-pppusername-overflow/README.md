# Stack-Based Buffer Overflow in Edimax BR-6208AC V2 formPPPoESetup Handler (`pppUserName`) — Return Address Control Verified

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The `formPPPoESetup` handler of the Edimax BR-6208AC V2 web management interface (firmware
1.03) copies the POST parameter `pppUserName` into a fixed-size stack buffer through **unbounded
`strcat()`** calls. An authenticated attacker gains **control of the saved return address at
offset 148** (verified with a De Bruijn pattern crash) and reliably crashes the web server;
because the firmware has no watchdog, the crash permanently disables the management interface
until power-cycled. The same vulnerable code block is **cloned into four WAN configuration
handlers** — all four share one root cause and must be fixed together.

## Affected Product

- Vendor: Edimax
- Product: BR-6208AC V2 (hardware version 2.0)
- Firmware: 1.03 — latest and final version (product is End-of-Life)

## Vulnerability Details

- Type: CWE-121 (Stack-based Buffer Overflow)
- Root cause (`sym.formPPPoESetup`, clone block @ 0x460ad0; buffer at sp+0x20):

```c
val = websGetVar(wp, "pppUserName", "");   // attacker-controlled
buf[0] = 0;                                // buf on stack (sp+0x20)
piece = val;
do {
    hash = strchr(piece, '#');
    if (hash) *hash = 0;
    strcat(buf, piece);                    // unbounded
    if (hash) { strcat(buf, "\#"); piece = hash + 1; }
} while (hash);
if (buf[0]) apmib_set(0x42, buf);          // overflow content then handled as the PPPoE username
```

### Clone block — one root cause, four handlers

Byte-identical instruction sequences (verified with rasm2 linear disassembly) exist in:

| handler | clone block | parameter | buffer |
|---|---|---|---|
| formPPPoESetup | 0x460ad0 | pppUserName | sp+0x20 |
| formPPTPSetup | 0x462148 | pptpUserName | sp+0x18 |
| formL2TPSetup | 0x45f87c | L2TPUserName | sp+0x18 |
| formWanTcpipSetup | 0x4645cc | pppUserName | sp+0x18 |

`formPPPoESetup` is reachable under the factory/default WAN configuration and is the endpoint
dynamically verified here. The other three are reachable when the device is configured for the
corresponding WAN type (PPTP/L2TP) — they are gated by the stored configuration, not by code.

### Measured control (qemu-user `-strace`, rehosted firmware 1.03)

| payload | result |
|---|---|
| 120 × `A` | request completes normally (no signal) |
| 160 × `A` | `SIGSEGV {si_code=1, si_addr=0x41414140}` → boa prints "caught SIGSEGV, dumping core" → kills itself with SIGIOT; webs process count: 0 |
| 400-byte De Bruijn B(62,4) pattern | `SIGSEGV {si_code=1, si_addr=0x4141416c}` |

`si_addr` is the instruction-fetch address, i.e. the value the CPU tried to execute at.
0x4141416c is the little-endian word `6c 41 41 41` = pattern bytes **"lAAA", which sit at
offset 148** of the De Bruijn sequence → **the saved return address lives at buf+148
(sp+0xB4)** and is fully attacker-controlled. The 120/160 crash threshold is consistent
(148 + 4 = 152).

## Proof of Concept (non-destructive)

`poc.py` (this directory) sends the threshold payload and verifies the kill:

```bash
python3 poc.py 192.168.2.1 admin:1234
# [*] baseline: GET / -> 302
# [*] sending pppUserName = 'A' * 160
# [+] web server is DEAD afterwards (connection refused) — overflow executed
```

On a stock device the crash occurs before the corrupted value is committed to flash, so no
configuration change persists; the service recovers on reboot. Run only against lab devices.

## Impact

- Attacker: authenticated web-admin user (factory default credentials `admin/1234` apply to
  un-hardened devices and are disclosed in the 401 realm — see `../01-webs-401-preauth-dos`).
- Demonstrated: program-counter control + persistent management-plane DoS.
- Feasible: full remote code execution via MIPS ROP — the binary is a large statically linked
  executable with no ASLR/PIE; no exploit is published here.

## Related Work

The same vulnerable clone block on the sibling model BR-6478AC (firmware 1.23) is covered by
**CVE-2026-10125** (formPPPoESetup), **CVE-2026-10165** (formWanTcpipSetup) and
**CVE-2026-9443** (formL2TPSetup). This report covers the independently built BR-6208AC V2
firmware and adds what the public sibling records do not contain: the exact return-address
offset (148, De Bruijn-verified), the four-handler clone-block root cause, the crash-threshold
measurements, and the WAN-mode reachability matrix. **CVE-2025-70161** (`pppUserName` command
injection in the *setWAN* handler of this model) is a different handler and a different
vulnerability class. Per-product CVE assignment is this CNA's established practice
(CVE-2025-15256/15257/15258 on this model).

## CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (High)**
C/I rated High on the basis of verified program-counter control plus standard MIPS ROP
conditions; A rated High on the verified persistent crash.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via a 513-point long-input fuzz over 20 goform handlers
(the only genuine crash found), strace-based crash attribution and rasm2 byte-exact static
analysis. Vendor notified: see top-level README.
