# VulDB Submission Sheet — BR-6208AC-cves

> Each vulnerability is submitted **separately** (one form per entry). Description is plain text
> (VulDB disables markup) — copy the fenced block verbatim, without the fence.

## Shared fields

| Field | Value |
|---|---|
| Vendor | `Edimax` (select the existing entry) |
| Product | `BR-6208AC` |
| Version or Commit | `1.03` (BR-6208AC **V2** hardware) |

---

## Entry 1 — Pre-authentication double-401 uClibc free() heap over-read → persistent DoS

| Field | Value |
|---|---|
| Vulnerability | `Out-of-bounds Read (CWE-125)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/BR-6208AC-cves/tree/main/01-webs-401-preauth-dos |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A pre-authentication denial of service vulnerability was discovered in Edimax BR-6208AC V2 firmware v1.03 (the latest and final firmware; the product is end-of-life). The web management server (bin/webs, a GoAhead-derived Boa/0.94.14rc21 running as root) sends the 401 Unauthorized response twice for any request carrying invalid HTTP Basic credentials to an authentication-protected page such as /index.asp. During connection teardown it calls free() on a request buffer; the bundled uClibc free() reads the next heap chunk header before checking the heap-top boundary, so when the freed chunk ends exactly at the program break (the steady state after a 401) it reads past brk into an unmapped page and the process dies with SIGSEGV (si_addr = brk+4, verified in two independent runs). Reproduction: curl -u admin:wrongpass http://192.168.2.1/index.asp returns 401; every subsequent request fails with connection refused because the web server process has exited. Crash reliability was verified 8/8 across credential variants (short/long passwords up to 1000 chars, empty username, empty password, Unicode, shell metacharacters); control cases (valid credentials, no credentials, pre-auth 400 rejections) do not crash. The firmware ships no watchdog or respawn mechanism (verified in inittab, init.d, crontab), so the management interface stays permanently down until the device is power-cycled; replaying after every reboot keeps it permanently unmanageable. The 401 responses additionally disclose the realm string "Default:admin/1234", advertising the factory default credentials. An unauthenticated network attacker can persistently deny the device's only management plane with a single HTTP request. Proposed CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5). Discovered by Zimo-666 via firmware rehosting and dynamic crash analysis.
```

---

## Entry 2 — formAccept `submit-url` command injection (root)

| Field | Value |
|---|---|
| Vulnerability | `OS Command Injection (CWE-78)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/BR-6208AC-cves/tree/main/02-formaccept-submit-url-cmdinj |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A command injection vulnerability was discovered in Edimax BR-6208AC V2 firmware v1.03 (the latest and final firmware; the product is end-of-life). The formAccept handler of the web management interface (/goform/formAccept) passes the value of the POST parameter submit-url directly to system() without any validation or sanitization; the handler body is only 156 bytes and the call is effectively system(websGetVar(wp, "submit-url", "")). An authenticated attacker can execute arbitrary shell commands with root privileges (the web server runs as root). Reproduction: curl -u admin:1234 --data-urlencode "submit-url=ping -c 3 <attacker-ip>" http://192.168.2.1/goform/formAccept returns HTTP 302 and ICMP echo requests from the router are observed at the attacker host; in a rehosted firmware environment a marker file was created as uid=0. Authentication requires the web admin credentials; the device ships with factory defaults admin/1234 which the 401 realm string actively discloses, so on un-hardened devices the issue is effectively pre-authentication. The same handler, parameter and root cause on the sibling model BR-6478AC (firmware 1.23) is covered by CVE-2026-9440; this report concerns the independently built BR-6208AC V2 firmware, and per-product assignment is this CNA's established practice (CVE-2025-15256, CVE-2025-15257, CVE-2025-15258 on this model). Proposed CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (7.2). Discovered by Zimo-666 via attack-surface mapping, static taint analysis and dynamic verification.
```

---

## Entry 3 — formWlbasic `rootAPmac` command injection (semicolon-only filter bypass)

| Field | Value |
|---|---|
| Vulnerability | `OS Command Injection (CWE-78)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/BR-6208AC-cves/tree/main/03-formwlbasic-rootapmac-cmdinj |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A command injection vulnerability was discovered in Edimax BR-6208AC V2 firmware v1.03 (the latest and final firmware; the product is end-of-life). When the parameter doConnectTest=1 is present, the formWlbasic handler (/goform/formWlbasic) embeds the value of rootAPmac into the shell command echo '<value>' > /tmp/apcli0_rootMAC and executes it via system(). The input filter rejects only the semicolon character (0x3b); single quotes, newlines and command substitution are not filtered, so the incomplete blacklist is trivially bypassed. Two independent escapes were dynamically verified as uid=0 in a rehosted firmware environment: closing the quote with x'$(cmd)'y and separating commands with embedded newlines; a control payload without quote closing executed nothing. Reproduction: curl -u admin:1234 --data-urlencode doConnectTest=1 --data-urlencode "rootAPmac=x'\$(ping -c 3 <attacker-ip>)'y" http://192.168.2.1/goform/formWlbasic results in ICMP echo requests from the router at the attacker host. Authentication requires the web admin credentials; factory defaults admin/1234 apply to un-hardened devices and are disclosed in the 401 realm. The same handler, parameter and root-cause class on the sibling model BR-6478AC (firmware 1.23) is covered by CVE-2026-10166; the semicolon-only filter mechanism and the two escape techniques are documented here for the first time, and per-product assignment is this CNA's established practice (CVE-2025-15256 previously covered the distinct formStaDrvSetup endpoint on this model). Proposed CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (7.2). Discovered by Zimo-666 via static taint analysis and dynamic verification.
```

---

## Entry 4 — formPPPoESetup `pppUserName` stack overflow (return-address control)

| Field | Value |
|---|---|
| Vulnerability | `Stack-based Buffer Overflow (CWE-121)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/BR-6208AC-cves/tree/main/04-formpppoesetup-pppusername-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A stack-based buffer overflow vulnerability was discovered in Edimax BR-6208AC V2 firmware v1.03 (the latest and final firmware; the product is end-of-life). The formPPPoESetup handler (/goform/formPPPoESetup) copies the value of the POST parameter pppUserName into a fixed-size stack buffer through unbounded strcat() calls inside a loop that splits the value on the '#' character. The saved return address is located 148 bytes into the attacker-controlled buffer: a 400-byte De Bruijn pattern crashes the process while executing at address 0x4141416c, exactly the pattern bytes at offset 148, proving control of the program counter. A 160-byte value reliably crashes the web server while a 120-byte value does not, consistent with the measured offset (148+4=152). The same vulnerable code block is cloned into three further WAN configuration handlers (formPPTPSetup/pptpUserName, formL2TPSetup/L2TPUserName, formWanTcpipSetup/pppUserName), reachable when the device is configured for the corresponding WAN mode; all four share one root cause and must be fixed together. The firmware has no watchdog, so the crash permanently disables the management interface until power-cycled, and the demonstrated program-counter control combined with the large statically linked binary and the absence of ASLR/PIE makes remote code execution feasible for an authenticated attacker (factory default credentials admin/1234 apply to un-hardened devices and are disclosed in the 401 realm). Reproduction: curl -u admin:1234 --data-urlencode "pppUserName=<160 x A>" http://192.168.2.1/goform/formPPPoESetup; every subsequent request fails with connection refused. The same clone block on the sibling model BR-6478AC (firmware 1.23) is covered by CVE-2026-10125, CVE-2026-10165 and CVE-2026-9443; this report adds the exact return-address offset, the clone-block root cause and the reachability matrix for BR-6208AC V2. CVE-2025-70161 concerns a different handler (setWAN) and a different vulnerability class (command injection) on this model and is unrelated. Per-product assignment is this CNA's established practice. Proposed CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (7.2). Discovered by Zimo-666 via a 513-point fuzz, strace crash attribution and byte-exact static analysis.
```

---

> **Model note.** `BR-6208AC V2` firmware 1.03 must not be confused with `BR-6208AC V1` 1.32, which is a
> different code base (V1 has handlers that do not exist in V2). Say "V2" in the Version field if the
> form allows free text.
