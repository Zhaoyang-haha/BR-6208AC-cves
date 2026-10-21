# BR-6208AC-cves — Security Advisories for Edimax BR-6208AC V2 (Firmware 1.03)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

Independent security research on the **Edimax BR-6208AC V2** wireless router (hardware v2.0,
firmware **1.03** — the latest and final version; the product is End-of-Life and receives no
further updates). Four vulnerabilities were discovered through firmware rehosting
(qemu-user + docker), full attack-surface mapping of the 105 goform handlers, static taint
analysis and dynamic verification. Each issue has its own directory with a full write-up and a
non-destructive proof of concept.

| # | Title | Type | Auth | Impact | CVE |
|---|---|---|---|---|---|
| 01 | [Web server double-401 uClibc free() heap over-read](01-webs-401-preauth-dos/) | CWE-125 | **Pre-auth** | Persistent DoS of the management plane (no watchdog) | CVE: Not assigned |
| 02 | [formAccept `submit-url` command injection](02-formaccept-submit-url-cmdinj/) | CWE-78 | Auth* | Root RCE (zero validation `system()`) | CVE: Not assigned |
| 03 | [formWlbasic `rootAPmac` command injection (semicolon-only filter bypass)](03-formwlbasic-rootapmac-cmdinj/) | CWE-78 | Auth* | Root RCE | CVE: Not assigned |
| 04 | [formPPPoESetup `pppUserName` stack overflow](04-formpppoesetup-pppusername-overflow/) | CWE-121 | Auth* | Return-address control (offset 148, verified) + persistent DoS | CVE: Not assigned |

\* Authentication requires the web-admin credentials. The device ships with factory defaults
`admin/1234`, which the 401 response realm actively discloses (issue 01); on un-hardened
devices issues 02–04 are therefore effectively pre-authentication.

## Sibling-model CVEs (BR-6478AC, firmware 1.23)

The same codebase family on the sibling model was assigned CVE-2026-9440 (formAccept),
CVE-2026-10166 (formWlbasic), CVE-2026-10125 / CVE-2026-10165 / CVE-2026-9443 (the WAN-setup
overflow clone block) in the June 2026 VulDB batch. The advisories here concern the
independently built **BR-6208AC V2** firmware and add analysis the public records lack
(measured return-address offset, clone-block root cause, trigger matrices). Issue 01 has no
sibling or prior coverage of any kind.

## Disclosure timeline

- 2026-10-12 — research completed, all four issues dynamically verified
- 2026-10-13 — public disclosure repository prepared
- Vendor notification (security@edimax.com / support@edimax.com) — pending
- 2026-10-13 — repository published; CVE identifiers requested via VulDB (CNA)

## Researcher

Zimo-666 — independent security researcher. All testing was performed in an isolated
environment against rehosted firmware; no production devices or third-party networks were
affected, and PoCs are non-destructive (crash PoCs recover on reboot and commit no
configuration changes).

---

## Repository files

| Path | Content |
|---|---|
| `01-webs-401-preauth-dos/` | Advisory + `poc.sh` — pre-auth heap over-read / management-plane DoS |
| `02-formaccept-submit-url-cmdinj/` | Advisory + `poc.sh` — `submit-url` command injection |
| `03-formwlbasic-rootapmac-cmdinj/` | Advisory + `poc.sh` — `rootAPmac` command injection |
| `04-formpppoesetup-pppusername-overflow/` | Advisory + `poc.py` — `pppUserName` stack overflow |

All PoCs are non-destructive, create only volatile state, and are intended for authorized testing
against devices you own or are explicitly permitted to test.
