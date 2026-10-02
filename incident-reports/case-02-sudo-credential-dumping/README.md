# Case 02: Sudo Abuse — Credential Dumping via Misconfigured Grant

![Status](https://img.shields.io/badge/status-completed-brightgreen) ![Focus](https://img.shields.io/badge/focus-SOC%20Operations-blue) ![Platform](https://img.shields.io/badge/platform-Linux-orange) ![Telemetry](https://img.shields.io/badge/telemetry-Wazuh%20%2B%20auditd-lightgrey) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

---

## Case at a Glance

| Field | Detail |
|---|---|
| **Victim host** | `ubuntu-victima` (192.168.1.46), Ubuntu 26.04 LTS, kernel 7.0.0-31-generic |
| **Compromised user** | `victima` (already holding valid, non-root access — continuation of Case 01's foothold) |
| **Severity** | Critical |
| **Initial condition** | Low-privilege user with a `sudo` grant broad enough to read any file as root |
| **Telemetry sources** | Wazuh (HIDS/SIEM) + `auditd` + `audisp-syslog` (custom pipeline built for this case) |
| **Key behaviors** | Privilege-level enumeration, OS credential dumping |
| **Detections generated** | 3 custom Wazuh rules (`100030`, `100031`, `100033`) |
| **Related case** | Case 03 (privilege escalation to root — same foothold, different technique) |

---

## Attack Flow

```
Privilege Enumeration          Credential Dumping
(sudo -l)                      (sudo cat /etc/shadow)
     ↓ auditd → audisp-syslog         ↓ sudo decoder (5402)
   rule 100031                      rule 100030
     ↓                                ↓
                 CORRELATION: recon → dump within 5 min
                          rule 100033 (critical)
```

---

## Contents

1. [Overview](#overview)
2. [Scenario](#scenario)
3. [Objectives](#objectives)
4. [Executive Summary](#executive-summary)
5. [Data Sources](#data-sources)
6. [Raw Event Timeline](#raw-event-timeline)
7. [Investigation](#investigation)
8. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
9. [Indicators of Attack (IOAs)](#indicators-of-attack-ioas)
10. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
11. [Incident Severity](#incident-severity)
12. [Incident Response Actions](#incident-response-actions)
13. [Detection Rules](#detection-rules)
14. [Final Incident Conclusion](#final-incident-conclusion)
15. [Skills Demonstrated](#skills-demonstrated)
16. [Disclaimer](#disclaimer)

---

## Overview

This case documents the first of two post-access privilege-escalation techniques executed against a host where the attacker already held valid, low-privilege access (the same foothold established in Case 01). It focuses on a specific, extremely common misconfiguration: a `sudo` grant broad enough to let a non-root user read any file on the system — including `/etc/shadow`. (Case 03 documents a second, independent technique — full root compromise via GTFOBins — against the same host.)

`sudo` usage is often either fully trusted or logged only at a generic, low-severity level in many SOC stacks. This case builds the detection layer needed to catch this specific misuse from scratch, closing that blind spot.

## Scenario

- **Victim host**: `ubuntu-victima`, Ubuntu 26.04 LTS, kernel `7.0.0-31-generic`, IP `192.168.1.46`.
- **Wazuh manager**: Docker container (`single-node-wazuh.manager-1`, `wazuh-docker/single-node` deploy) on a separate Windows PC.
- **Compromised user**: `victima`, holding a `sudo` grant broad enough to read any file as root.
- **Starting condition**: valid shell access already obtained (continuation of the foothold from Case 01).
- **Notable environment detail**: `sudo` on this build is `sudo-rs` (the Rust reimplementation, version 0.2.13), not classic C sudo — a completely different codebase and versioning scheme, with direct consequences for how it needs to be audited (see Investigation).

## Objectives

1. Measure how much of a `sudo`-based credential-dumping sequence the stock Wazuh/`auth.log` pipeline captures, and how much requires custom engineering.
2. Build host-level visibility into `sudo` command arguments independent of `sudo-rs`'s own (insufficient) logging.
3. Correlate the two-step pattern — privilege recon, then credential access — into a single high-confidence alert.

## Executive Summary

The attacker first enumerated their own `sudo` privileges (`sudo -l`), then used that same access to dump `/etc/shadow`. Neither step was reliably visible through the stock logging pipeline, so a custom `auditd → audisp-syslog → Wazuh` pipeline was built specifically to capture full command-line arguments for `sudo` invocations. A correlation rule was then built to escalate the two-step pattern — recon followed by dumping within 5 minutes — from two low/medium-severity events into a single critical alert, since neither event alone is a reliable indicator (admins run `sudo -l` and `sudo cat` routinely) but the specific sequence is.

Severity is classified as **Critical**: the dumped file exposes every local account's password hash for offline cracking, from a single, specific `sudo` misconfiguration.

## Data Sources

| Source | What it provides |
|---|---|
| `auditd` (custom execve watch on `sudo`, persisted in `/etc/audit/rules.d/`) | Full command-line visibility for `sudo` invocations, independent of `sudo-rs`'s own logging |
| `audisp-syslog` | Converts multi-line `EXECVE` audit records into single-line syslog entries Wazuh ingests via its existing `syslog`-format `localfile` |
| Wazuh — sudo decoder (rule `5402`) | Native "successful sudo to root" detection — generic, low severity, insufficient alone |
| Wazuh — custom rules `100030`/`100031`/`100033` | Purpose-built detection for this case, validated with `wazuh-logtest` and live traffic |

## Raw Event Timeline

| Event | rule.id | Level |
|---|---|---|
| Recon: `sudo -l` (privilege enumeration) | `100031` | 3 |
| `sudo cat /etc/shadow` (credential dump) | `100030` | 12 |
| **Correlation**: recon → dump within 300s | `100033` | 13 |

## Investigation

`sudo-rs`'s own logging (`/var/log/auth.log`) was insufficient to reliably capture full command-line arguments for correlation purposes, so a custom `auditd` execve watch was built and made persistent across reboots:

```bash
echo '-a always,exit -F arch=b64 -S execve -F exe=/usr/lib/cargo/bin/sudo -k sudo_correct' \
  | sudo tee /etc/audit/rules.d/sudo_correct.rules
sudo augenrules --load
```

Note the executable path: `/usr/lib/cargo/bin/sudo`, not `/usr/bin/sudo`. This build uses `sudo-rs` (the Rust reimplementation of sudo, version 0.2.13 — a completely different codebase and versioning scheme from classic C sudo 1.9.x), and auditing the wrong path silently produces zero events.

`audisp-syslog` forwards these records into `/var/log/syslog`, which Wazuh already reads via an existing `syslog`-format `localfile` — no new log source needed to be registered.

Two engineering problems were resolved building this pipeline:
- Wazuh rejects `frequency="1"` (`Invalid frequency: 1. Must be higher than 1 and lower than 10000.`) — the correlation rule (`100033`) was written with `frequency="2"`.
- Rule `100031` (the `sudo -l` recon rule) silently failed to match for an extended period despite many regex attempts. The eventual root cause: **literal double-quote characters inside a `<match type="pcre2">` block cause silent non-matches in this environment**, even escaped (`\"`) or as an entity (`&quot;`). The fix was to avoid quote characters entirely and match on unquoted positional substrings (`EXECVE.*argc=2.*sudo.*-l`) — a pattern this host's later detection work (Case 03) also follows.

Both rules were confirmed firing in sequence against real `sudo -l` → `sudo cat /etc/shadow` activity, with the correlation rule (`100033`) escalating the pair to critical severity.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Compromised user | `victima` | Low-privilege account with a `sudo` grant broad enough to read any file |
| Dumped credential file | `/etc/shadow` | Read via `sudo cat` |
| `sudo` implementation | `sudo-rs` 0.2.13 (`/usr/lib/cargo/bin/sudo`) | Rust reimplementation, not classic sudo |

## Indicators of Attack (IOAs)

| Behavior | Why it's suspicious |
|---|---|
| `sudo -l` immediately followed by `sudo cat /etc/shadow` within minutes | Privilege enumeration directly followed by credential access — not how routine admin work is typically sequenced |

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Tactic | Evidence | Confidence |
|---|---|---|---|---|---|
| Privilege discovery | Permission Groups Discovery: Local Groups | T1069.001 | Discovery | Rule `100031` (`sudo -l`) | High |
| Privilege escalation | Abuse Elevation Control Mechanism: Sudo and Admin | T1548.003 | Privilege Escalation | Overly broad `sudo` grant used to read root-owned files as a non-root user | High |
| Credential access | OS Credential Dumping: /etc/Password and /etc/shadow | T1003.008 | Credential Access | Rule `100030` (`/etc/shadow` read) | High |
| Composite chain | Recon → Privilege Escalation → Credential Dumping | T1069.001 → T1548.003 → T1003.008 | Discovery → Privilege Escalation → Credential Access | Rule `100033` (correlation) | High |

Mapping notes: T1548.003 is its own row because the broad `sudo` grant is itself the escalation mechanism — reading `/etc/shadow` as a low-privilege user only works because `sudo` hands over root privileges with no file-scope restriction. This is the same underlying abuse-of-sudo category documented more narrowly in Case 03 (a single-binary grant exploited via GTFOBins). No dedicated rule isolates this step alone; it's evidenced jointly by rules `100030`/`100033` and the known sudoers configuration.

## Incident Severity

**Classification: Critical.**

Rationale: the dumped file exposes every local account's password hash for offline cracking — a single `sudo` misconfiguration with system-wide credential-exposure impact, not limited to the compromised account itself.

## Incident Response Actions

1. **Containment**: reversible containment (revoke the specific `sudo` grant, force session termination) plus immediate escalation to the IR team — a credential-dumping event can indicate the account itself is fully compromised and warrants root-cause investigation, not automatic full isolation at Tier 1.
2. **Evidence preservation**: export `rule.id: 100030, 100031, 100033` events and the raw `auditd`/`audisp-syslog` records before log rotation.
3. **Eradication**: audit and tighten the `sudoers` grant for `victima` — scope file-read access explicitly rather than granting broad `sudo` rights.
4. **Recovery**: rotate all local account passwords — the `/etc/shadow` dump must be treated as if every hash is now subject to offline cracking, regardless of individual password strength.
5. **Post-incident**: formalize a `sudoers` review process for any grant broad enough to read arbitrary files.

## Detection Rules

```xml
<group name="local,recon_sudo,">
<rule id="100031" level="3">
  <match type="pcre2">EXECVE.*argc=2.*sudo.*-l</match>
  <description>Sudo privilege recon (sudo -l)</description>
  <mitre><id>T1069.001</id></mitre>
</rule>
</group>

<rule id="100030" level="12">
  <if_sid>5402</if_sid>
  <match>/etc/shadow|/etc/passwd</match>
  <description>Credential dumping via sudo</description>
  <mitre><id>T1548.003</id><id>T1003.008</id></mitre>
</rule>

<group name="local,credential_dump_chain,">
<rule id="100033" level="13" frequency="2" timeframe="300">
  <if_sid>5402</if_sid>
  <if_matched_group>recon_sudo</if_matched_group>
  <match>/etc/shadow|/etc/passwd</match>
  <description>Full attack chain: recon followed by credential dumping</description>
  <mitre><id>T1069.001</id><id>T1548.003</id><id>T1003.008</id></mitre>
</rule>
</group>
```
*Validated* with `wazuh-logtest` and live traffic: a real `sudo -l` → `sudo cat /etc/shadow` sequence fired `100031` then `100030` then `100033` in order.

**SIEM-agnostic version**: converted to **Sigma** format — see [`detection-rules/sigma/`](detection-rules/sigma/).

## Final Incident Conclusion

This case demonstrates how a common, easy-to-overlook `sudo` misconfiguration (a file-read grant broader than intended) enables full credential dumping, and how closing the resulting visibility gap required building a dedicated `auditd`-based pipeline rather than relying on `sudo`'s own logging. The correlation rule built here — escalating two individually-ambiguous events into one high-confidence alert based on sequence and timing — is the same design pattern reused and extended in Case 03.

## Skills Demonstrated

- Building a custom `auditd → audisp-syslog → Wazuh` visibility pipeline from scratch, including persistence across reboots
- Root-causing a silent detection failure at the engine level (a `pcre2` quote-character bug) through systematic, reproducible testing
- Designing a correlation rule that converts two low-confidence events into one high-confidence alert based on sequence and timing
- Adapting detection engineering to a non-standard `sudo` implementation (`sudo-rs`) by verifying the real binary path rather than assuming GNU/classic Linux defaults
- Mapping technical evidence to MITRE ATT&CK with explicit confidence levels

## Disclaimer

This is a **real, deliberately executed** incident in an isolated home lab, for educational and portfolio purposes. None of the machines or data involved belong to a third party or a production environment.
