# Case 06 — LLMNR / NBT-NS / mDNS Poisoning & NTLMv2 Credential Capture

**Name Resolution Poisoning → NTLMv2 Hash Capture → Multi-Layer Detection → Protocol Hardening**

| | |
|---|---|
| **Status** | Complete |
| **Focus** | Blue Team / Detection Engineering / Hardening |
| **Platform** | Windows Server 2022 Active Directory |
| **Telemetry** | Windows Security Event Log + Sysmon + Wazuh + network capture (pcap) |
| **Framework** | MITRE ATT&CK — T1557.001 |

> **Scope note:** this case covers a single, self-contained engagement against the lab Domain Controller: an adversary-in-the-middle name-resolution poisoning attack with Responder, the capture of an NTLMv2 authentication, its analysis across three telemetry layers, and the hardening steps that neutralize the technique at its root.

---

## Case at a Glance

| Field | Detail |
|---|---|
| **Victim host** | DC01 (192.168.1.50) — Domain Controller, `soclab.local` |
| **Attacker host** | Kali Linux (192.168.1.47) |
| **Technique** | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (T1557.001) |
| **Severity** | High |
| **Initial artifact** | Poisoned LLMNR/NBT-NS/mDNS responses from a non-authoritative host |
| **Telemetry sources** | Windows Security Event Log (4625) + Sysmon (EID 3) + Wazuh + tcpdump/Wireshark pcap |
| **Key behaviors** | Multicast/broadcast name-resolution poisoning, spoofing a file server, NTLMv2 challenge-response capture |
| **Captured secret** | NTLMv2-SSP hash of a domain authentication attempt |
| **Detection outcome** | Network layer: full attack visible in pcap. Host layer: Wazuh captured the authentication attempt (4625). Sysmon: blind by design — see Investigation |
| **Tools** | Responder 3.2.2.0, tcpdump, Wireshark, Wazuh |

---

## Attack Flow

```
Victim queries a name        Attacker answers first        Victim authenticates
that DNS cannot resolve  →   "that host is me"         →   to the fake SMB server   →   NTLMv2 hash
(dir \\badname\share)        (LLMNR/NBT-NS/mDNS                (challenge-response)         captured
     ↓                        poisoning, IPv4 + IPv6)              ↓                            ↓
 no DNS record →              ↓ visible in pcap             Wazuh: Event 4625          Responder logs
 falls back to               (query response from          (failed network logon)     NTLMv2-SSP hash
 multicast/broadcast          192.168.1.47)                      ↓                           ↓
                                                            Sysmon EID 3: NOT logged    offline crack
                                                            (PID 4 / System filtered)   or relay
```

---

## Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Objectives](#objectives)
- [Executive Summary](#executive-summary)
- [Data Sources](#data-sources)
- [Raw Event Timeline](#raw-event-timeline)
- [Investigation](#investigation)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [Indicators of Attack (IOAs)](#indicators-of-attack-ioas)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Incident Severity](#incident-severity)
- [Mitigation & Hardening](#mitigation--hardening)
- [Detection Rules](#detection-rules)
- [Detection Roadmap](#detection-roadmap)
- [Final Incident Conclusion](#final-incident-conclusion)
- [Skills Demonstrated](#skills-demonstrated)
- [Disclaimer](#disclaimer)

---

## Overview

This case documents an end-to-end adversary-in-the-middle attack based on name-resolution poisoning, executed against the lab Domain Controller and analyzed from the defender's perspective. Responder was used to poison LLMNR, NBT-NS and mDNS traffic, impersonate a non-existent file server, and capture an NTLMv2 authentication from the Domain Controller. The engagement then assessed detection coverage across three independent telemetry layers — network (pcap), SIEM (Wazuh) and host (Sysmon) — surfacing a structural lesson: the poisoning itself is a network-layer event largely invisible to host-based tooling, and a well-intentioned anti-noise filter in a standard Sysmon configuration left the resulting SMB connection unlogged. The case closes with the hardening procedure that neutralizes the technique at its source.

## Scenario

- **Domain:** `soclab.local`, Windows Server 2022 Active Directory, Domain Controller DC01 (192.168.1.50).
- **Attacker host:** Kali Linux (192.168.1.47), running Responder 3.2.2.0.
- **Starting point:** network access to the DC's segment; no credentials required for the poisoning phase.
- **Vulnerability:** Windows' fallback name-resolution chain. When DNS fails to resolve a name, Windows falls back to LLMNR (UDP 5355), NBT-NS (UDP 137) and mDNS (UDP 5353) — multicast/broadcast protocols with no authentication, where any host on the segment can claim to be the requested name.
- **End state:** an NTLMv2-SSP hash of a domain authentication attempt captured by the attacker, usable for offline cracking or, with SMB signing absent, NTLM relay.

## Objectives

- Execute a controlled LLMNR/NBT-NS/mDNS poisoning attack and capture a domain NTLMv2 authentication.
- Assess detection coverage across network, SIEM and host layers independently.
- Identify and root-cause any blind spots in the current detection stack.
- Document the hardening procedure that eliminates the technique at the protocol level.

## Executive Summary

Responder was launched against the DC's network segment. When the Domain Controller attempted to resolve a non-existent hostname, DNS returned no record and Windows fell back to multicast/broadcast name resolution. Responder answered first — on both IPv4 and IPv6 — claiming to be the requested host, and redirected the victim to the attacker's fake SMB server. When the DC attempted to authenticate to that server, it handed over an **NTLMv2-SSP challenge-response hash**, which Responder captured and logged.

Critically, the captured hash is **NTLMv2**, which is not usable for Pass-the-Hash (unlike raw NT hashes dumped from the SAM/NTDS). Its two viable uses are **offline cracking** (dictionary/brute-force, only effective against weak passwords) and **NTLM relay** (forwarding the authentication live to another host, which SMB signing defeats).

Detection was assessed across three layers:

- **Network (pcap):** the full attack was visible in crude form. A packet capture showed the victim's `query` for the hostname (broadcast/multicast) and the attacker's `query response` claiming that name — a response that, from an IP that is not the legitimate server, should not exist on a healthy network.
- **SIEM (Wazuh):** the poisoning itself generated no host log, but the *consequence* did. The victim's failed authentication to the fake server produced **Event 4625** (failed logon) on the DC, surfaced by native Wazuh rule 60122.
- **Host (Sysmon):** the SMB connection that followed the poisoning was **not logged** by Sysmon — not a misconfiguration in the strict sense, but a consequence of the SwiftOnSecurity `NetworkConnect` rule excluding the System process (PID 4), which is precisely the process a Windows client uses for SMB.

The central finding: **name-resolution poisoning lives in the network layer and is near-invisible to host telemetry.** A single sensor never sees the whole attack — only the combination of network, SIEM and host tells the full story. This is defense-in-depth demonstrated in practice, not in theory.

## Data Sources

| Source | What it provides |
|---|---|
| Network capture (tcpdump → Wireshark) | The raw poisoning: victim `query` vs. attacker `query response` for the spoofed name, on IPv4 and IPv6 |
| Windows Security Event Log (DC01) | Event 4625 — failed network logon produced by the victim authenticating to the fake SMB server |
| Wazuh — native rules | Rule 60122 (`Logon failure - Unknown user or bad password`) over Event 4625 |
| Sysmon (DC01) | Event ID 3 (Network Connection) — assessed; the attack's SMB connection was filtered by the active config (see Investigation) |
| Responder logs | `NTLMv2-SSP` hash captured on disk; poisoned-answer log for LLMNR/NBT-NS/mDNS |

## Raw Event Timeline

| Time | Event | Source / rule.id | Level |
|---|---|---|---|
| T+0 | Responder started on the DC's segment, poisoning LLMNR / NBT-NS / mDNS | Responder | — |
| T+0 | DC issues name query for a non-existent host (DNS fails → multicast/broadcast fallback) | pcap (LLMNR/NBT-NS) | — |
| T+0 | Attacker (192.168.1.47) sends poisoned `query response` claiming the name — IPv4 and IPv6 | pcap (`query response`) | — |
| T+0 | DC opens SMB session to the fake server and attempts NTLM authentication | Responder | — |
| T+0 | `NTLMv2-SSP` hash captured and written to Responder logs | Responder | — |
| T+0 | Failed network logon registered on the DC | Event 4625 → Wazuh 60122 | 5 |
| T+0 | SMB connection (TCP 445) from the attack **not** recorded by Sysmon | Sysmon EID 3 (filtered — PID 4) | — |

**Evidence:** `screenshots/responder-poisoned-answers.png` — Responder sending poisoned LLMNR/NBT-NS/mDNS answers to the DC (192.168.1.50) for a non-existent name, on IPv4 and IPv6.

## Investigation

**Name-resolution poisoning (the root cause).** When the Domain Controller tried to resolve a hostname with no DNS record, Windows did not stop at the DNS failure — it fell back to the local resolution chain: LLMNR (UDP 5355), NBT-NS (UDP 137) and mDNS (UDP 5353). These are multicast/broadcast protocols with no authentication: the query goes out to the entire segment, and any listening host can answer "that name is me." Responder was that listening host, and it answered first. This fallback-to-unauthenticated-multicast is the original sin of the technique — the attacker only has to respond before anyone else, and on a well-run network, nobody else should be answering at all.

**Packet-level confirmation.** A packet capture (tcpdump → Wireshark, filtered on `llmnr || nbns`) showed the attack in its crudest form. The sequence was unambiguous:

- The victim (192.168.1.50) sent a `Standard query` for the hostname to the multicast/broadcast address — a legitimate, if risky, fallback.
- The attacker (192.168.1.47) replied with a `Standard query response` mapping that name to its own IP — the poisoning. Inspecting the response payload confirmed the `Answers` section: `Name: <spoofed host>` → `Address: 192.168.1.47`, with a short TTL of 30 seconds and `Flags: No error`, so the victim accepted it as valid.

A key observation: the poisoning occurred on **both IPv4 and IPv6** simultaneously. Responder answered the IPv6 query (`fe80::...`) and the IPv4 query with the same lie, always redirecting to the attacker's IPv4 address. IPv6 is a frequently overlooked vector in defenses that only consider IPv4.

> **Evidence:**
> - `screenshots/wireshark-poisoned-response.png` — packets 114–117: the DC's `Standard query` for `DC01` followed immediately by the attacker's `Standard query response` (`A DC01 A 192.168.1.47`) on both IPv6 and IPv4.
> - `screenshots/wireshark-response-payload.png` — the expanded LLMNR response payload, `Answers → DC01 → Address: 192.168.1.47`, TTL 30s, `Flags: No error`.
> - `screenshots/wireshark-queries-only.png` — a separate capture showing only the victim's broadcast/multicast `query` traffic (no attacker running), useful as the "before" baseline.

Distinguishing signal from noise was itself a lesson: alongside the poisoned responses, the capture contained legitimate `Registration` NBNS packets — the DC announcing its own names to the network. These are benign background traffic, not part of the attack. Separating legitimate name registration from malicious name poisoning is exactly the kind of judgment a SOC analyst applies to a noisy capture.

**NTLMv2 capture.** Once the victim believed the attacker's host was the requested server, it opened an SMB session and attempted to authenticate. Over SMB, Windows never sends the password in cleartext — it sends an NTLMv2 challenge-response, computed from the account's hash against a challenge issued by the server. Acting as the (fake) server, Responder issued a challenge, received the signed response, and captured it: a full `NTLMv2-SSP` hash tied to the authenticating account. The hash is **NTLMv2**, which rules out Pass-the-Hash; its realistic uses are offline cracking or live NTLM relay.

**SIEM-layer detection (Wazuh).** The poisoning itself produced no host-side event — it is pure network traffic and never touches a Windows event log. But the *consequence* did: the victim's authentication against the fake server failed and produced **Event 4625** (`Logon failure`), surfaced by native Wazuh rule 60122. Reading the event's fields (logon type, source, target account) reconstructs the tail of the attack from the host's perspective. This is the complement to the pcap: the network capture shows the poisoning, Wazuh shows the resulting authentication attempt.

**Host-layer blind spot (Sysmon) — root-caused.** Sysmon was running with a standard SwiftOnSecurity configuration, and `Network connection: enabled` was confirmed. Yet no Event ID 3 (Network Connection) was recorded for the attack's SMB connection. Root cause: the config's `NetworkConnect` rule for anomalous outbound SMB combines three conditions —

```
Protocol = tcp  AND  DestinationPort = 445  AND  ProcessId is not 4
```

— and **excludes the System process (PID 4)** to avoid the enormous noise of normal SMB traffic. The problem is that a Windows client's SMB connections *are made by the System process (PID 4)*. The connection the DC opened to the attacker's fake server therefore matched the exclusion and was never logged. This is a genuine defender's paradox: a rule literally named "Outbound SMB anomalous connections," built to catch anomalous SMB, is blind to the most common LLMNR→SMB attack because its anti-noise filter removes exactly the traffic the attack generates. Every filter added to reduce noise is a potential gap an attacker can use.

**The cross-layer conclusion.** No single layer saw the whole attack. The network capture saw the poisoning; Wazuh saw the authentication attempt; Sysmon had a structural blind spot by design. This is defense-in-depth as a necessity rather than a luxury — each sensor covers the gap left by another. It is also worth noting that this technique is genuinely hard to detect from the host: even commercial EDR platforms struggle with Responder precisely because the poisoning is passive and network-resident.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Attacker IP | 192.168.1.47 | Source of all poisoned responses and the fake SMB server |
| Poisoning tool | Responder 3.2.2.0 | LLMNR/NBT-NS/mDNS poisoner and NTLM capture server |
| Captured artifact | `NTLMv2-SSP` hash | Challenge-response of a domain authentication attempt |
| Affected protocols | LLMNR (UDP 5355), NBT-NS (UDP 137), mDNS (UDP 5353) | Name-resolution fallback abused for poisoning |
| Host event | Event 4625 on DC01 | Failed network logon produced by the captured authentication |

## Indicators of Attack (IOAs)

| Behavior | Why it's suspicious |
|---|---|
| A single host answering LLMNR/NBT-NS/mDNS queries for names it does not own | On a healthy network, nobody should answer a query for a non-existent name — any `query response` is anomalous by definition |
| `query response` for name resolution originating from a non-infrastructure IP | The answering host is neither the DC nor a legitimate file server |
| Poisoned responses on both IPv4 and IPv6 for the same name | Responder-style dual-stack poisoning; IPv6 is a common blind spot |
| A burst of poisoned answers to many distinct names from one source in seconds | Volume and breadth of responses from a single host is a strong Responder signature |
| Event 4625 on a Domain Controller correlated in time with anomalous LLMNR/NBT-NS traffic | Failed authentication to a rogue server following a poisoned name resolution |

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Tactic | Evidence | Confidence |
|---|---|---|---|---|---|
| Name-resolution poisoning | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 | Credential Access / Collection | pcap: `query response` from 192.168.1.47; Responder logs | High |
| Credential capture | Network Sniffing (NTLMv2 challenge-response capture) | T1040 | Credential Access | `NTLMv2-SSP` hash in Responder logs | High |
| Forced authentication | Forced Authentication (victim coerced into authenticating to attacker) | T1187 | Credential Access | Event 4625 on DC01; SMB session to fake server | High |

## Incident Severity

**Classification: High.**

Rationale: name-resolution poisoning against a Domain Controller is a high-severity scenario because the credentials in transit belong to a privileged context. The captured NTLMv2 hash is not directly reusable (Pass-the-Hash does not apply to NTLMv2), which keeps this below Critical; but if the password is weak enough to crack offline, or if SMB signing is absent and the hash can be relayed live, the path to privileged access is short. A Domain Controller initiating outbound SMB to a non-infrastructure host is, in a production environment, one of the strongest indicators of credential-theft activity.

## Mitigation & Hardening

Name-resolution poisoning is best eliminated at the protocol level rather than merely detected. Because the attack abuses three distinct fallback protocols, a complete mitigation must close **all three** — disabling only LLMNR (the most well-known) leaves NBT-NS and mDNS open, and the attacker simply pivots to them.

**1. Disable LLMNR (Group Policy or registry).**

Group Policy: `Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution = Enabled`.

Registry equivalent:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -Value 0 -Type DWord
```

**2. Disable NBT-NS (per network adapter).**

```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
$adapters | ForEach-Object { $_.SetTcpipNetbios(2) }   # 2 = disable NetBIOS over TCP/IP
```

For managed environments, NBT-NS can also be disabled via DHCP option 001 (Microsoft Disable NetBIOS option) so the setting is pushed centrally to all clients.

**3. Disable mDNS (registry).**

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
  -Name "EnableMDNS" -Value 0 -Type DWord
```

**4. Enforce SMB signing (defeats NTLM relay).**

Even if a hash is captured, SMB signing prevents it from being relayed to another host. Enforce it on both client and server via Group Policy, or:

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

**5. Enforce LDAP signing + channel binding on Domain Controllers.** Closes the complementary relay path toward LDAP/LDAPS, which SMB signing alone does not cover.

**6. (Defense-in-depth) Deploy a trusted-responder detection rule.** In an environment where LLMNR/NBT-NS are disabled, *any* response to those queries is anomalous by definition — a near-zero-false-positive network detection to complement the hardening above.

> **Verification principle:** after applying the protocol disables, the correct validation is to re-run the poisoning tool and confirm that no poisoned answers are produced for any of the three protocols and that no NTLMv2 hash is captured — i.e., the attack is neutralized at the source, not merely detected.

## Detection Rules

**Rule status at a glance:**

| Detection | Layer | Status |
|---|---|---|
| Event 4625 → Wazuh native rule 60122 | SIEM / host | ✅ Fired on real attack data |
| Network pcap analysis (LLMNR/NBT-NS poisoned responses) | Network | ✅ Manually confirmed in Wireshark |
| Sysmon EID 3 (SMB connection) | Host | ⚠️ Blind by config (PID 4 exclusion) — see roadmap |
| Suricata / NIDS signature for poisoned responses | Network | 🧪 Planned — not yet deployed in this environment |

**Native detection (Wazuh rule 60122).** The failed authentication produced by the attack surfaced through Wazuh's built-in rule 60122 over Event 4625:

```
rule.id: 60122
rule.description: "Logon failure - Unknown user or bad password."
rule.level: 5
data.win.system.eventID: 4625
```

Enrichment fields worth reviewing on each 4625 to tie it to this technique: `logonType` (network = 3), `ipAddress` (attacker source), `targetUserName` (the account whose authentication was captured).

> **Evidence:** `screenshots/wazuh-rule-60122-logon-failure.png` — live Wazuh dashboard hit for rule 60122 (Event 4625, `Logon failure - Unknown user or bad password`) during the engagement window.

**Network detection (pcap).** The attack is unambiguous at the packet layer. The detection logic that generalizes it: *a `query response` to an LLMNR (UDP 5355) or NBT-NS (UDP 137) query, originating from any host that is not an authorized responder.* On a hardened network where these protocols are disabled, the authorized-responder list is empty, so every response is an alert — a high-fidelity, low-false-positive signal. This is the planned Suricata/NIDS rule (see roadmap).

**Host detection (Sysmon) — documented gap.** Sysmon's `NetworkConnect` logging was active but excluded PID 4 (the System process that performs SMB), so the attack's SMB connection was not recorded. See the roadmap for the tuning that closes this.

## Detection Roadmap

Concrete next steps to raise this case's detection coverage, in priority order:

1. **Deploy a NIDS (Suricata) on the DC segment** and author a rule alerting on LLMNR/NBT-NS `query response` from non-authorized responders. This is the highest-fidelity detection for the poisoning phase, which host telemetry cannot see. Validate by replaying the captured pcap offline (`suricata -r capture.pcap`).
2. **Tune Sysmon to capture the attack's SMB connection** — add targeted logging for SMB (445) toward non-infrastructure destinations, or move the "anomalous destination" correlation to the SIEM (where the list of legitimate servers is maintained in one place, rather than editing XML on every host). This resolves the PID 4 blind spot without drowning in the noise the original exclusion was designed to prevent.
3. **Monitor the `EnableMulticast` registry key** (the one disabled during hardening) for re-activation — a known adversary technique to quietly re-open LLMNR after it has been turned off.
4. **Correlate 4625 bursts with anomalous name-resolution traffic** in Wazuh, turning the generic "failed logon" into a technique-specific "forced authentication following name poisoning" alert.

## Final Incident Conclusion

This case reconstructs a complete name-resolution poisoning attack against a Domain Controller, from the poisoned multicast response to the captured NTLMv2 authentication, and assesses detection across three independent telemetry layers. The engagement confirmed the defining property of the technique: it is a network-layer attack that is near-invisible to host-based tooling. Wazuh captured the authentication *attempt* (Event 4625), the packet capture exposed the *poisoning* itself, and Sysmon exhibited a structural blind spot rooted in a standard anti-noise filter excluding the System process. The most valuable lesson is architectural: no single sensor tells the whole story, and an anti-noise filter can quietly become a blind spot. The technique is eliminated not by detection alone but by closing all three fallback protocols at the host and enforcing SMB/LDAP signing to defeat relay — the hardening procedure documented above. Deploying a NIDS rule for the poisoning phase is the primary detection follow-up for this lab.

## Skills Demonstrated

- Execution and analysis of an adversary-in-the-middle name-resolution poisoning attack (T1557.001) end to end
- Packet-level analysis in Wireshark: isolating poisoned `query response` traffic, reading the LLMNR/mDNS response payload, and distinguishing malicious poisoning from legitimate NBNS name registration
- Understanding of the NTLMv2 challenge-response mechanism and why the captured hash is crack/relay-only, not Pass-the-Hash
- Multi-layer detection assessment (network / SIEM / host) with explicit mapping of which layer sees which phase
- Root-cause analysis of a host-detection blind spot (Sysmon `NetworkConnect` PID 4 exclusion) rather than accepting an absence of alerts at face value
- Protocol-level hardening: disabling LLMNR, NBT-NS and mDNS, plus SMB and LDAP signing to defeat relay, as a complete (not partial) mitigation
- Mapping the chain to MITRE ATT&CK with explicit confidence levels
- Writing a professional incident report with honest documentation of detection gaps and a concrete remediation roadmap

## Disclaimer

This is a real, deliberately executed incident in an isolated home lab, for educational and portfolio purposes. None of the machines or data involved belong to a third party or a production environment. All accounts, credentials, and domain objects referenced are fictitious, created specifically for this exercise.
