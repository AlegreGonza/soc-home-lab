# Sigma Detection Rules — Case 05

SIEM-agnostic detection logic for the Case 05 Active Directory attack chain (password spray → credential exposure → NTDS dump / DCSync → Golden Ticket), written in [Sigma](https://github.com/SigmaHQ/sigma) format before being translated into native Wazuh rules.

## Workflow

1. Draft new detections here first, as Sigma YAML.
2. Validate the logic conceptually (does the `detection` block actually express the behavior we want to catch?).
3. Convert / hand-translate to the native syntax of the SIEM in use (Wazuh XML rules — see `../wazuh/`).
4. Test the native rule (`wazuh-logtest` for Wazuh, though it proved unreliable for Windows eventchannel data — real production data was used instead) before deploying.
5. Keep both versions in the repo, cross-referenced (see each rule's "Native mapping notes" section).

## Rules in this folder

| File | Covers | MITRE ATT&CK | Native Wazuh rule | Status |
|---|---|---|---|---|
| `kerberos_bruteforce_t1110_001.yml` | 4+ failed Kerberos pre-auth (4771) against the SAME account from one source in 60s | T1110.001 | Custom rules `100050` / `100051` | **Validated against real data** — fired consistently across real Kerbrute runs |
| `kerberos_password_spray_t1110_003.yml` | 10+ failed Kerberos pre-auth (4771) against DIFFERENT accounts from one source in 60s | T1110.003 | Custom rule `100052` | **Validated against real data** — fired 2026-10-11 19:58:31 against a real spray |
| `dcsync_t1003_006.yml` | Directory replication rights (DS-Replication-Get-Changes[-All]) used by a non-DC principal | T1003.006 | Custom rules `100060` / `100061` | Drafted, conceptually validated — not yet confirmed against live Event 4662 (SACL audit prerequisite not configured yet) |
| `kerberoasting_t1558_003.yml` | TGS request with RC4 encryption + Kerberoasting ticket options | T1558.003 | Custom rule `100062` | Drafted, conceptually validated — pending live confirmation against `GetUserSPNs.py` traffic |
| `golden_ticket_t1558_001.yml` | Network logon (type 3) with zeroed LogonGuid | T1558.001 | Custom rule `100063` | Drafted — weak single-signal heuristic, documented limitation, no live validation |

All five rules are documented in detail, with real evidence and known limitations, in the [Case 05 incident report](../../README.md).

## Detection roadmap carried from the incident report

- **DCSync (100060/100061)** cannot generate any alert until a SACL audit entry for the two replication extended rights is configured on the domain object — this is not enabled by Windows default auditing and must be set explicitly (via `auditpol` + ADSI Edit). Without it, Event ID 4662 is never written, regardless of how correct the detection logic is. This is the top item on the case's detection roadmap.
- **Kerberoasting (100062)** needs a formal `GetUserSPNs.py` run against `svc_sql` to confirm the Event 4769/RC4 pattern live.
- **Golden Ticket (`golden_ticket_t1558_001.yml`)** is intentionally documented as a weak heuristic. A real Golden Ticket detection capability requires correlating ticket lifetime and reuse patterns that the Windows Security Event Log does not expose with sufficient granularity on its own — tracked as future work (see the rule's "Native mapping notes").
