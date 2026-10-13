# Case 05: Active Directory Total Compromise — Enumeration → Password Spray → Credential Exposure → NTDS Dump / DCSync → Golden Ticket

![Status](https://img.shields.io/badge/status-completed-brightgreen)
![Focus](https://img.shields.io/badge/focus-Active%20Directory-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20Server%202022%20%2B%20Kali%20Linux-orange)
![Telemetry](https://img.shields.io/badge/telemetry-Windows%20Event%20Log%20%2B%20Sysmon%20%2B%20Wazuh-lightgrey)
![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

> **Scope note:** this report supersedes two earlier session logs (previously tracked as "Case 04" and "Case 05"). It is a single attack chain against the same domain, executed across two lab sessions (Oct 11-12, 2026): not two incidents, but one continuous engagement that escalated from unauthenticated reconnaissance to total, persistent domain compromise.

## Case at a Glance

| Field | Detail |
|---|---|
| Victim host | `DC01` (192.168.1.50) — Domain Controller, `soclab.local` |
| Attacker host | Kali Linux (192.168.1.47) |
| Engagement window | 2026-10-11 → 2026-10-12 |
| Compromised accounts | `bdiaz` (low privilege) → `atorres` (low privilege, exposed credential) → `Administrator` → `sysadmin` (both Domain Admin–equivalent) |
| Severity | Critical |
| Initial artifact | Password spray / brute-force against Kerberos pre-auth (Event 4771) |
| Telemetry sources | Windows Security Event Log + Sysmon + Wazuh (native and custom rules) |
| Key behaviors | Enumeration, password spray, failed lateral movement, credential exposed in an AD attribute, escalation to Domain Admin, full NTDS.dit dump, DCSync targeted at `krbtgt`, Golden Ticket forging and use |
| Detections generated | Custom rules 100050–100052 (Kerberos brute-force/spray) + 100060–100063 (DCSync/Kerberoasting/Golden Ticket, drafted) + native 60205, 92652, 61618 |
| Tools | Kerbrute, netexec (nxc), Impacket (`lookupsid.py`, `psexec.py`, `secretsdump.py`, `ticketer.py`), Wazuh |

## Attack Flow

```
Day 1 — Initial access and first total compromise
Reconnaissance          Password Spray /         Authenticated recon    Credential exposure
(nmap, netexec,     →   Brute-force Kerberos  →  (netexec --users,  →   (AD Description
 kerbrute userenum)     (kerbrute)                --pass-pol)             field: atorres)
     ↓ no native           ↓ 100050/100051/        ↓ no native              ↓ no native
       event                 100052 (Wazuh)           event                    event
                                                                                  ↓
                        Escalation to Domain     →  Full NTDS.dit dump
                        Admin (Administrator —      (netexec --ntds, T1003.003)
                         exact origin not            includes krbtgt
                         captured in real time)          ↓ 92652 (NTLM) +
                                                             61618 (Sysmon:
                                                             RemoteRegistry) ← strong detection

Day 2 — Lateral movement, targeted DCSync and persistence
Failed lateral            Second route to Domain    DCSync targeted at       Golden Ticket
movement (psexec,     →   Admin (sysadmin,       →  krbtgt (secretsdump  →   forged and used
bdiaz, no local admin)     already privileged)         -just-dc-user)           (ticketer.py)
     ↓ no native           ↓ 92652 (NTLM)               ↓ 92652 (NTLM,           ↓ NOT detected
       event                                              heuristic, not           (no SACL,
                                                            DCSync-specific)         no correlation rule)
```

## Contents

- Overview
- Scenario
- Objectives
- Executive Summary
- Data Sources
- Raw Event Timeline
- Investigation
- Indicators of Compromise (IOCs)
- Indicators of Attack (IOAs)
- MITRE ATT&CK Mapping
- Incident Severity
- Incident Response Actions
- Detection Rules
- Detection Roadmap
- Final Incident Conclusion
- Skills Demonstrated
- Disclaimer

## Overview

This case documents a complete Active Directory compromise chain executed end-to-end against a personal home lab, across two consecutive sessions: reconnaissance and user enumeration, password spray/brute-force against Kerberos, authenticated low-privilege reconnaissance, discovery of a plaintext credential exposed in an AD attribute, escalation to Domain Admin, a full NTDS.dit dump, a failed lateral-movement attempt, a DCSync attack targeted specifically at `krbtgt`, and finally the forging and use of a Golden Ticket for unauthenticated persistence in the domain. Detection coverage was assessed at every stage, revealing both real wins (Kerberos brute-force/spray, and the NTDS dump via Sysmon) and a critical structural gap: Windows does not audit directory replication rights by default, so the DCSync left only a generic, indirect trail.

## Scenario

- **Domain:** `soclab.local`, Windows Server 2022 Active Directory, Domain Controller `DC01` (192.168.1.50).
- **Attacker host:** Kali Linux (192.168.1.47).
- **Starting point:** no credentials, only network access to the DC's segment.
- **Vulnerability chain:** weak domain passwords against a targeted spray; a second account with its password stored in plaintext in the AD `Description` attribute, readable by any authenticated user via SAMR; and the absence of SACL auditing on directory replication rights, which left the attack's most critical step (DCSync) effectively invisible.
- **End state:** possession of the NTLM hash and AES keys for `krbtgt`, obtained via two independent routes (full NTDS.dit dump and targeted DCSync), and a forged Golden Ticket granting persistent, unauthenticated access as any domain account, including `Administrator`.

## Objectives

- Reconstruct the full attack timeline, from credential-less initial enumeration to total, persistent domain compromise.
- Identify Indicators of Compromise (IOCs) and Indicators of Attack (IOAs) at each phase.
- Map every phase to MITRE ATT&CK techniques.
- Document the visibility blind spots in the current detection stack, particularly around directory-service auditing.
- Draft and validate custom Wazuh detection rules for Kerberos brute-force/spray, DCSync, Kerberoasting, and Golden Ticket usage.
- Propose concrete mitigations for each phase of the chain.

## Executive Summary

The engagement started with no credentials: network reconnaissance and user enumeration via Kerbrute, followed by a formal password spray/brute-force against Kerberos pre-auth that, despite not cracking any password on its first run, did generate real detection (custom rules 100050/100051/100052) and a valuable finding of its own — a miscalibrated spray ended up locking out all six target accounts, an accidental DoS vector against legitimate users. A later, narrower run did find a valid credential (`bdiaz`).

With `bdiaz`, authenticated low-privilege reconnaissance revealed a second account (`atorres`) with its password stored in plaintext in the Active Directory `Description` field — a misconfiguration pattern documented in real ransomware incidents, not a lab invention. That second credential was the bridge to an account with Domain Admin privileges. The exact origin of the `Administrator` credential used for the first mass dump was not captured in real time — it remains an open item, consistent with this lab's methodology of honestly documenting what wasn't captured live rather than reconstructing it after the fact — but it is reasonable to assume it followed the same pattern of pivoting through exposed credentials and/or password reuse, since that pattern had already been confirmed working once in the same chain.

With that level of access, a full NTDS.dit dump (`netexec --ntds`) was executed, extracting all 9 NTLM hashes in the domain, including `krbtgt` — the highest-impact compromise possible in an AD domain. This stage did generate a specific, valuable detection: Sysmon flagged the anomalous startup of `svchost.exe -k localService -p -s RemoteRegistry`, the service `netexec --ntds` needs to enable in order to read the registry boot key.

In the second session, with the domain already effectively compromised, lateral movement with `bdiaz` via `psexec` was attempted — and failed, for lack of local administrative privileges, confirming that a valid domain credential alone is not enough for SMB-based lateral movement. Using an account with Domain Admin–equivalent privileges (`sysadmin`), a DCSync attack targeted specifically at `krbtgt` was executed (`secretsdump.py -just-dc-user krbtgt`) — the textbook route for this objective, stealthier than the full dump because it never touches `lsass.exe` or the NTDS.dit file on disk. That action, and the subsequent forging and use of a Golden Ticket, only triggered the generic NTLM heuristic (rule 92652) — a coincidence of Impacket's tooling authenticating over NTLM, not a technique-specific detection. Native DCSync detection (Event 4662 with the replication GUIDs) requires a SACL audit rule that **was not configured** on the domain object at the time of the attack — a structural gap, not a tooling failure. Severity is classified as **Critical**: full, persistent domain compromise was achieved.

## Data Sources

| Source | What it provides |
|---|---|
| Windows Security Event Log (DC01) | Authentication (4624, 4662, 4768/4769, 4771), account lockouts (4740), directory-service access |
| Sysmon (DC01) | Process creation — detected the anomalous startup of `RemoteRegistry` during the NTDS dump |
| Wazuh — native rules | Audit-failure correlation (60205), pass-the-hash/NTLM heuristic (92652), suspicious Sysmon process (61618) |
| Wazuh — custom rules | Kerberos brute-force (100050/100051, validated) and password spray (100052, validated with real data on 2026-10-11) over Event 4771; DCSync (100060/100061), Kerberoasting (100062) and a Golden Ticket heuristic (100063), drafted in Sigma and Wazuh, pending live validation |
| Impacket / Kerbrute / netexec output | Direct evidence of enumeration, spray, credential dumping, and ticket forging |

## Raw Event Timeline

| Time | Event | rule.id | Level |
|---|---|---|---|
| 2026-10-11 (session 1) | nmap + netexec — network reconnaissance, `soclab.local` domain confirmed via LDAP | — | no event |
| 2026-10-11 | `kerbrute userenum` — 7 real users confirmed | — | no event (never sends a password) |
| 2026-10-11 | `kerbrute passwordspray` / `bruteforce` — multiple runs against Kerberos pre-auth | 60205 | 10 |
| 2026-10-11 | Event 4771 (failed pre-auth) repeated against the same account | 100050 → 100051 | 3 → 12 |
| 2026-10-11 19:58:31 | Event 4771 repeated against different accounts from the same source (10+ in 60s) | 100052 | 12 |
| 2026-10-11 | Event 4740 — lockout of all 6 target accounts (accidental DoS from a margin miscalculation) | — | — |
| 2026-10-11 | Narrower `kerbrute bruteforce` run — valid credential found: `bdiaz:Soclab2026!!` | — | — |
| 2026-10-11 | `netexec --users`/`--pass-pol` with `bdiaz` — authenticated user and password-policy enumeration | — | no event (authenticated SAMR, structural gap) |
| 2026-10-11 | `atorres`'s `Description` field exposes `Correo2026!!` in plaintext; successful login with that credential | 92652 | 6 |
| 2026-10-11 | `Administrator` credential (`43677284Agg`) obtained — exact origin not captured in real time | — | — |
| 2026-10-11 | `netexec --ntds` — full NTDS.dit dump, 9/10 hashes including `krbtgt` | 92652 (login) + 61618 (Sysmon RemoteRegistry) | 6 / 12 |
| 2026-10-12 | `psexec` with `bdiaz` — fails (no local admin, `SVCManager` denied) | — | no event |
| 2026-10-12 17:14:46.589 | `ANONYMOUS LOGON` — NTLM, possible pass-the-hash (RPC null-session phase preceding DCSync) | 92652 | 6 |
| 2026-10-12 17:14:46.638 | Windows User Logoff | 60137 | 3 |
| 2026-10-12 17:14:46.681 / 46.872 | `Administrator` — NTLM authentication, possible pass-the-hash | 92652 | 6 |
| 2026-10-12 17:14:48.071 | Windows User Logoff | 60137 | 3 |
| 2026-10-12 17:14:53.293 / 53.427 | `sysadmin` — NTLM authentication, possible pass-the-hash (DCSync against `krbtgt`) | 92652 | 6 |
| 2026-10-12 17:14:53.627 | Windows User Logoff | 60137 | 3 |
| 2026-10-12 | `krbtgt` NTLM hash and AES keys extracted via targeted DCSync | — | no technique-specific event (SACL not configured) |
| 2026-10-12 | Golden Ticket forged and used to authenticate as `Administrator` | — | no event (no detection implemented for this step) |

## Investigation

**Reconnaissance and enumeration.** `nmap` and `netexec` confirmed the `soclab.local` domain via LDAP (389) on host `DC01`. `kerbrute userenum` identified 7 real, enabled accounts without generating any native event, since it never sends a password — the stealthiest phase of the entire attack. In a real-world scenario this user list usually comes from OSINT (LinkedIn, Hunter.io), not name brute-forcing.

**Password spray / brute-force against Kerberos.** The formal spray against all 6 accounts with three dictionary passwords (`Soclab2026!!`, `Password2026!`, `Bienvenido123!`) and a `user:user` pattern found no valid credential on its first run — an honest, expected result against 12+ character passwords. However, the margin calculation went wrong: despite budgeting under the lockout threshold (5 attempts), all 6 accounts ended up locked out (Event 4740), likely because Kerberos retries the AS-REQ (UDP→TCP) under certain conditions, duplicating the real failure count against the lockout counter. This is a valuable finding in its own right: **a miscalibrated spray is an accidental DoS vector** against legitimate users, and it left a lesson to budget 2 attempts (not 4) in future sprays.

This phase did generate solid detection: Event 4771 (failed pre-auth) repeated against the same account triggered the custom correlation 100050→100051 (confirmed brute-force), and repeated against different accounts from the same source it triggered 100052 (password spray) — both validated with real data from actual Kerbrute runs, not just in theory.

A later, narrower run (5 candidates instead of a full dictionary) did find the real credential: `bdiaz:Soclab2026!!`. It was confirmed not to be a shared password across accounts (`atorres:Soclab2026!!` failed).

**Authenticated reconnaissance and failed lateral movement.** With `bdiaz`, `netexec --users`/`--pass-pol` allowed low-privilege reconnaissance without needing admin rights — and immediately confirmed that `krbtgt` is the "Key Distribution Center Service Account," the highest-impact target for any subsequent Kerberos attack. This authenticated enumeration via SAMR generated no native event: the Windows Security Event Log has no Event ID for "an authenticated account queried the user/group list" — an industry-wide structural gap, only covered in practice by Identity Threat Detection tooling such as Microsoft Defender for Identity. A later lateral-movement attempt with `psexec` using `bdiaz` failed: without local administrator access, `ADMIN$`/`C$` weren't writable and the Service Control Manager could not be opened remotely — confirming that a valid domain credential alone is not enough for SMB-based lateral movement.

**Credential exposed in an AD attribute.** The same authenticated enumeration revealed that the `atorres` account had its password (`Correo2026!!`) stored in plaintext in the `Description` field — a real misconfiguration pattern, documented in public ransomware post-mortems and AD-pentesting writeups (it is, for example, the basis of HackTheBox's "Resolute" box), not a lab invention. Successful login with that credential triggered the native rule 92652, same as with `bdiaz` — but the discovery itself, being a SAMR attribute read, was invisible again due to the same structural gap.

**Escalation to Domain Admin.** From there, the `Administrator` credential (`43677284Agg`) was obtained, confirmed with full administrative privileges over the DC (`netexec` explicitly flags it as `Pwn3d!`). The exact method by which this specific credential was reached was not recorded at the time — it is this report's main open item (see "Detection Roadmap") — but, given that the pattern of pivoting through poorly secured domain credentials had already been confirmed once, it is reasonable (though not confirmable from log evidence) that it followed an equivalent route: password reuse, another exposed attribute, or group membership discovered during enumeration (the tiered groups `SOC-Tier1`/`SOC-Tier2`/`SOC-Admins` had already been identified in the domain). A later session also used a second account with equivalent privileges, `sysadmin`, for the DCSync and Golden Ticket stages — both accounts (`Administrator` and `sysadmin`) represent the same level of access reached in the engagement, simply exercised in different steps of the chain.

**Full NTDS.dit dump (T1003.003).** With `Administrator`, `netexec --ntds` extracted 9 of 10 NTLM hashes for the entire domain, including `Administrator`, `Guest`, **`krbtgt`**, the 6 real user accounts, and `DC01$`. This is the maximum possible impact in this scenario: with the `krbtgt` hash, an attacker can generate valid Kerberos tickets for any domain account indefinitely, even after individual password rotations (it requires rotating the `krbtgt` hash twice to invalidate existing Golden Tickets). This stage left the case's most valuable detection: Sysmon flagged the startup of `svchost.exe -k localService -p -s RemoteRegistry` — the `RemoteRegistry` service, normally inactive on a DC, is needed to remotely read the registry boot key (`SYSTEM` hive) that decrypts the NTDS.dit hashes, and its anomalous startup triggered the native rule 61618 (level 12). Unlike SAMR enumeration (invisible), here the technique's specific *mechanism* — not just the generic login preceding it — left a clear trail.

**Targeted DCSync against `krbtgt` (T1003.006).** In the second session, with `sysadmin`, the objective of obtaining the `krbtgt` secret was repeated, but this time via the "textbook" DCSync route: `secretsdump.py -just-dc-user krbtgt` abuses the Directory Replication Service (DRS) protocol to directly ask the DC to replicate that secret, never touching `lsass.exe` or the NTDS.dit file on disk — stealthier than the full dump already executed the day before. The technique-specific detection (Event 4662 with the `DS-Replication-Get-Changes`/`-All` GUIDs in the `Properties` field) **was not generated**, because the SACL audit rule on the domain object was not configured at the time of the attack. The only detection obtained was, again, the generic NTLM heuristic (92652) — the same symptom that had already fired for the earlier escalation, with no signal distinguishing this particular event as directory-replication abuse.

**Golden Ticket forging and use (T1558.001).** With the `krbtgt` hash and the domain SID in hand, a Golden Ticket was forged and used to authenticate as `Administrator` without presenting any password or prior Kerberos ticket. No detection fired in the current environment: there was no SACL/4662 visibility into the preceding DCSync to correlate against, and no rule dedicated to anomalous TGT characteristics (unusually long lifetime, zeroed `LogonGuid`, logons for accounts with no prior Kerberos activity) was deployed at the time. This is the clearest blind spot in the entire case: the single highest-impact action of the whole chain left the weakest evidentiary trail.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Attacker IP | 192.168.1.47 | Source of all malicious traffic |
| Low-privilege account (foothold) | `bdiaz` | Real credential found after a narrow spray; no local admin |
| Account with exposed credential | `atorres` | Password in plaintext in the AD `Description` attribute |
| Elevated accounts used | `Administrator`, `sysadmin` | NTDS dump, DCSync, and ticket forging |
| Domain SID | `S-1-5-21-1654450598-2873889453-2981870735` | Required input to forge the Golden Ticket |
| `krbtgt` NTLM hash | `a41ba86527ddae17dfe2ad9985718437` | Compromised signing key for all Kerberos tickets in the domain |
| Tooling | Kerbrute, netexec, Impacket (`lookupsid.py`, `psexec.py`, `secretsdump.py`, `ticketer.py`) | Standard, publicly documented AD-attack tooling |

## Indicators of Attack (IOAs)

| Behavior | Why it's suspicious |
|---|---|
| Multiple failed Kerberos pre-auth attempts (4771) against the same account, or against many different accounts, from the same source in a short window | Classic signature of brute-force (100051) or password spray (100052) |
| Full domain user/group enumeration via RPC/SAMR from a single low-privilege session | Reconnaissance pattern preceding targeted credential attacks |
| `psexec` against a host where the account has no admin-share access | Failed lateral-movement probe — often followed by privilege-escalation attempts, as seen here |
| Directory-replication rights (`DS-Replication-Get-Changes[-All]`) invoked by an account other than a Domain Controller machine account | Textbook DCSync signature — should never originate from a non-DC principal |
| `RemoteRegistry` service startup on a DC, outside known maintenance windows | Technical step required to read the boot key during a remote NTDS.dit dump |
| NTLM authentication pattern from accounts that normally authenticate via Kerberos in a domain-joined environment | Indicates tooling that bypasses normal interactive logon (Impacket-style remote execution/credential dumping) |
| Successful authentication for a privileged account with no prior TGT-issuance activity for that session | Potential indicator of a forged (Golden Ticket) rather than legitimately issued TGT |

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Tactic | Evidence | Confidence |
|---|---|---|---|---|---|
| User enumeration | Account Discovery: Domain Account | T1087.002 | Discovery | `kerbrute userenum`; no native event | High |
| Password spray / brute-force | Brute Force: Password Spraying / Password Guessing | T1110.003 / T1110.001 | Credential Access | Rules 100050/100051/100052 over Event 4771 | High |
| Post-compromise reconnaissance | Account Discovery (via SAMR) | T1087.002 | Discovery | `netexec --users`/`--pass-pol`; no native event | High |
| Failed lateral movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement | `psexec` error (`SVCManager` denied) | High |
| Credential exposure | Credentials In Files (analogous — AD attribute, not a file) | T1552.001 | Credential Access | `netexec --users` output, `Description` field | High |
| Escalation | Valid Accounts: Domain Accounts | T1078.002 | Privilege Escalation / Defense Evasion | Rule 92652, successful `Administrator`/`sysadmin` logons | High |
| Credential dumping (full) | OS Credential Dumping: NTDS | T1003.003 | Credential Access | `netexec --ntds`; Sysmon 61618 (RemoteRegistry) | High |
| Credential dumping (targeted) | OS Credential Dumping: DCSync | T1003.006 | Credential Access | `secretsdump.py -just-dc-user krbtgt` | High |
| Persistence | Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Credential Access / Persistence | `krbtgt` hash + SID in hand; ticket forged and used (no native event) | High (attacker side); Low (detection side — no telemetry captured) |

## Incident Severity

**Classification: Critical.**

**Rationale:** the `krbtgt` account was compromised via two independent routes, and a Golden Ticket was forged and used. This represents the maximum possible level of compromise for an Active Directory domain: persistent, unauthenticated access as any account, surviving individual password resets, and requiring a double `krbtgt` rotation (more than 10 hours apart) to fully remediate. While contained to a lab environment, the chain faithfully replicates a real-world total domain compromise.

## Incident Response Actions

- **Containment:** isolate the DC from further unauthorized DRS requests; disable or reset the accounts used in the chain (`bdiaz`, `atorres`, `sysadmin`).
- **Evidence preservation:** export Security Event Log entries (4624, 4662 if present, 4768/4769, 4771, 4740) and Wazuh alerts (occurrences of 100050-100052, 92652, 61618) covering the full engagement window, before log rotation.
- **Eradication:** **rotate the `krbtgt` password twice**, more than 10 hours apart, to invalidate any ticket forged with the compromised hash. Remove the plaintext credential from the AD `Description` attribute and audit every other account for the same pattern.
- **Recovery:** force a password reset for every privileged account touched during the engagement; review Domain Admins group membership for unexpected additions; unlock and restore the lockout policy to its original values if it was accidentally relaxed.
- **Post-incident:** close the documented gaps — configure the SACL audit rule for `DS-Replication-Get-Changes[-All]` on the domain object (Event 4662), and deploy the Golden Ticket heuristic (anomalous `LogonGuid`/ticket lifetime) going forward.
- **Hardening:** restrict `Replicating Directory Changes`/`Replicating Directory Changes All` rights to Domain Controller machine accounts and strictly necessary service accounts only; implement a tiered administration model (Tier 0/1/2) so a single compromised workstation credential cannot reach Domain Admin; prohibit storing credentials in AD attributes via policy and periodic review.

## Detection Rules

All rules in this case share the same custom Wazuh ID range (100050-100063), grouped by stage of the chain:

**Rules 100050-100052 — Kerberos Brute-Force / Password Spray (Event 4771):**

```xml
<group name="kerberos,windows,">

  <rule id="100050" level="3">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^4771$</field>
    <description>Kerberos pre-authentication failed (possible bad password attempt).</description>
    <mitre><id>T1110.003</id></mitre>
  </rule>

  <rule id="100051" level="12" frequency="4" timeframe="60">
    <if_matched_sid>100050</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>Possible Kerberos Brute-Force: 4+ failed pre-auth attempts against the SAME account from the same source in 60s.</description>
    <mitre><id>T1110.001</id></mitre>
    <group>kerberos_bruteforce_confirmed</group>
  </rule>

  <rule id="100052" level="12" frequency="10" timeframe="60">
    <if_matched_sid>100050</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <different_field>win.eventdata.targetUserName</different_field>
    <description>Possible Kerberos Password Spray: 10+ failed pre-auth attempts against DIFFERENT accounts from the same source in 60s.</description>
    <mitre><id>T1110.003</id></mitre>
    <ignore>60</ignore>
  </rule>

</group>
```

**Status: 100050, 100051 and 100052 validated with real production data** (not just `wazuh-logtest`, which proved unreliable for this event type). 100051 fired consistently against real Kerbrute runs; 100052 fired on 2026-10-11 19:58:31 against a real spray (10+ failures, different accounts, same source).

**Rules 100060/100061 — DCSync (Event ID 4662):**

```xml
<group name="active_directory,windows,">

  <rule id="100060" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
    <description>Possible DCSync attack: directory replication rights used by $(win.eventdata.subjectUserName).</description>
    <mitre><id>T1003.006</id></mitre>
    <options>no_full_log</options>
  </rule>

  <rule id="100061" level="0">
    <if_sid>100060</if_sid>
    <field name="win.eventdata.subjectUserName" type="pcre2">\$$</field>
    <description>DCSync rights used by a machine account (legitimate Domain Controller) - excluded.</description>
    <options>no_full_log</options>
  </rule>

</group>
```

**Rule 100062 — Kerberoasting (Event ID 4769, RC4 encryption):**

```xml
<rule id="100062" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketOptions">0x40810000</field>
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <description>Possible Kerberoasting: TGS requested with RC4 encryption for $(win.eventdata.serviceName) by $(win.eventdata.targetUserName).</description>
  <mitre><id>T1558.003</id></mitre>
  <options>no_full_log</options>
</rule>
```

**Rule 100063 — Golden Ticket, heuristic (Event ID 4624, zeroed LogonGuid):**

```xml
<rule id="100063" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.logonGuid">^\{00000000-0000-0000-0000-000000000000\}$</field>
  <description>Possible Golden Ticket usage: network logon with zeroed LogonGuid for $(win.eventdata.targetUserName).</description>
  <mitre><id>T1558.001</id></mitre>
  <options>no_full_log</options>
</rule>
```

**Status: 100060-100063 designed, written in Wazuh and Sigma, and conceptually validated against this engagement's real evidence** (each rule was built directly on the observed behavior of this chain's `secretsdump.py`, `GetUserSPNs.py` and `ticketer.py`, not generically). Confirmation against a live Event 4662/4769/4624 is the next operational milestone on the detection roadmap below.

**SIEM-agnostic version:** all five rules (100050-100052, 100060-100063) have a Sigma version for portability — see `detection-rules/sigma/` in this case folder (DCSync, Kerberoasting, Golden Ticket, Kerberos brute-force and password spray). Native Wazuh XML is under `detection-rules/wazuh/`.

**Screenshot:** `screenshots/wazuh-rule-100052-password-spray.png` — live Wazuh dashboard hit for rule 100052 (Kerberos Password Spray), confirming the detection fired against real attack traffic on 2026-10-11.

## Detection Roadmap

Concrete next steps to move this case's detection coverage from "designed" to "confirmed live," in priority order:

1. **Enable SACL auditing on the domain object** (`auditpol` + ADSI Edit, procedure already defined) so Event 4662 starts being generated, then repeat the DCSync to confirm 100060/100061 fire against real data.
2. **Run `GetUserSPNs.py` against `svc_sql`** (already identified as a candidate during enumeration) as a formal step, to confirm 100062 against a real Event 4769 with RC4 encryption.
3. **Strengthen 100063 (Golden Ticket)** by correlating the current `LogonGuid` heuristic with ticket lifetime from 4768/4769, raising it from a single-signal heuristic to a higher-confidence detection.
4. **Confirm the exact origin of the `Administrator` credential** used on day 1 — currently documented as a reasonable hypothesis, pending log-based confirmation if this case is used as a formal reference.
5. **Investigate the firewall blind spot** (closed ports leaving no trace in `pfirewall.log`, despite well-configured logging) — not blocking for this case, but still open.

## Final Incident Conclusion

This case demonstrates a complete Active Directory kill chain, from credential-less enumeration to total, persistent domain compromise via Golden Ticket forging, executed across two lab sessions as a single continuous engagement. The investigation confirmed a real-world misconfiguration pattern (credentials stored in a directory attribute) and a critical, structural detection gap: Windows does not audit directory-replication rights by default, meaning DCSync — one of the highest-impact credential-access techniques against AD — is invisible to a stack relying solely on default Windows auditing. The only detection achieved during the privileged-access portion of the chain was a generic NTLM heuristic, correct in flagging anomalous behavior but imprecise in naming the actual technique — with the notable exception of the NTDS dump, where Sysmon did capture the specific technical mechanism (the `RemoteRegistry` startup). Closing this gap (SACL configuration for 4662, correlation-based Golden Ticket detection, and ultimately a dedicated identity-threat-detection tool) is documented as the primary follow-up work for this lab.

## Skills Demonstrated

- Execution and analysis of a complete Active Directory attack chain (reconnaissance, initial access, lateral movement, credential access, privilege escalation, persistence)
- Tuning Wazuh correlation rules for Kerberos brute-force vs. password spray, including debugging a real correlation-engine bug (`if_matched_group`) with research into official GitHub issues
- Identification of a real AD misconfiguration pattern (credentials in directory attributes), cross-referenced against public incident writeups
- DCSync and Golden Ticket mechanics: understanding of the Directory Replication Service protocol and Kerberos ticket signing
- Writing Wazuh/Sigma detection rules, with explicit documentation of limitations and false-positive handling
- Root-cause analysis of detection gaps (missing SACL auditing, structural SAMR gap) rather than accepting an absence of alerts at face value
- Mapping a full technique chain to MITRE ATT&CK with explicit confidence levels
- Writing a professional incident report (SANS PICERL / NIST SP 800-61 style), including honest documentation of evidence gaps rather than papering over them

## Disclaimer

This is a real, deliberately executed incident in an isolated home lab, for educational and portfolio purposes. None of the machines or data involved belong to a third party or a production environment. All accounts, credentials, and domain objects referenced are fictitious, created specifically for this exercise.
