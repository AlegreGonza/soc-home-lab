# SOC Home Lab â€” Suricata + Wazuh + TheHive + Cortex

![Status](https://img.shields.io/badge/status-in%20progress-yellow) ![Focus](https://img.shields.io/badge/focus-SOC%20Tier%201-blue) ![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20Docker-orange) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

A self-built detection and incident-response lab, put together to learn and demonstrate real SOC Tier 1 skills: not tutorials with pre-made datasets, but live attacks executed against real machines, detected, investigated, and documented end to end.

This repo is a **work in progress**. It grows one use case at a time â€” each new attack scenario adds its own detection rules, its own investigation, and its own write-up. Nothing here is a finished product; it's a running log of a SOC analyst learning by building.

---

## Incident cases

| # | Case | MITRE ATT&CK | Status |
|---|---|---|---|
| 01 | [SSH Brute Force + Data Exfiltration](incident-reports/case-01-bruteforce-exfiltration/) | T1595 Â· T1110.001 Â· T1078.003 Â· T1083 Â· T1005 Â· T1048.002 Â· T1070.004 | âœ… Completed |
| 02 | [Sudo Abuse — Credential Dumping](incident-reports/case-02-sudo-credential-dumping/) | T1069.001 · T1548.003 · T1003.008 | ✅ Completed |
| 03 | [Privilege Escalation — GTFOBins Abuse of a Restricted Sudo Binary](incident-reports/case-03-gtfobins/) | T1069.001 · T1548.003 · T1059.004 | ✅ Completed |
> Note: the port-scan scenario originally numbered "02" is already fully covered inside Case 01's own report (reconnaissance phase), so it doesn't get a separate entry.

---

## Why this project exists

The goal is a first job as a **SOC Tier 1 Analyst**. Instead of collecting certificates first and building later, this lab flips that order: every skill (log correlation, detection engineering, incident documentation, SOAR automation) is learned by solving a real problem that came up while building or attacking this environment â€” including the infrastructure failures along the way, which turned into some of the best material here (see the troubleshooting notes inside each case).

## Architecture

```
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚   Kali Linux (Attacker)  â”‚
                    â”‚      192.168.1.47        â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â”‚ attacks (nmap, Hydra, ssh, scp...)
                                 â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚  Ubuntu Server (Victim)  â”‚
                    â”‚      192.168.1.46        â”‚
                    â”‚  Suricata (NIDS)          â”‚
                    â”‚  Wazuh Agent (HIDS/FIM)   â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â”‚ logs / alerts
                                 â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚   Wazuh Manager (Docker) â”‚
                    â”‚   Windows host           â”‚
                    â”‚   SIEM + correlation      â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â”‚ high-confidence alerts
                                 â”‚ (Wazuh â†’ TheHive integration)
                                 â–¼
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚  TheHive + Cortex (VM)   â”‚
                    â”‚     192.168.1.49         â”‚
                    â”‚  Case management + SOAR  â”‚
                    â”‚  enrichment (Docker)     â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

| Host | Role | Stack |
|---|---|---|
| Kali Linux (`192.168.1.47`) | Attacker | nmap, Hydra, ssh/scp |
| Ubuntu Server (`192.168.1.46`) | Victim | Suricata (NIDS), Wazuh agent (HIDS/FIM) |
| Windows PC (Docker) | Wazuh Manager | `wazuh-docker/single-node`, SIEM + correlation engine |
| VM (`192.168.1.49`) | SOAR | TheHive (case management), Cortex (enrichment), Elasticsearch |

Each attack scenario is executed live against a real machine, detected in real time, then investigated and written up â€” not built backwards from a synthetic dataset. Every write-up follows a consistent format: scenario, timeline of raw events, investigation narrative, IOCs, IOAs, MITRE ATT&CK mapping, severity, response actions, the detection rule(s) involved, and skills demonstrated. New scenarios get added over time as the lab grows.

## What's already working

- **Network + host detection**: Suricata (NIDS) and Wazuh (HIDS/SIEM), correlating alerts from both layers.
- **File Integrity Monitoring (FIM)**: realtime watch on sensitive directories, independent of command-level auditing.
- **Custom detection rule**: a purpose-built Wazuh rule for fast SSH brute-force detection (see [Case 01 detection rules](incident-reports/case-01-bruteforce-exfiltration/#detection-rules)), validated with `wazuh-logtest`.
- **SOAR automation**: a Wazuh â†’ TheHive integration that auto-promotes high-confidence alerts straight to a Case, skipping manual triage.
- **SIEM-agnostic detection logic**: new detections are drafted first in [Sigma](https://github.com/SigmaHQ/sigma) format, then converted to native Wazuh syntax. Each case keeps its own `detection-rules/` folder alongside its report.

## Documented blind spots

Part of the value of this lab is being honest about what the current stack does **not** catch:
- Commands run without `sudo` leave no trace in the command-audit pipeline.
- Encrypted SSH/SCP traffic hides the content and nature of a file transfer from both NIDS and application logs.

These are tracked as future work rather than hidden â€” see each case's own report for details.

## Repository structure

```
soc-home-lab/
â”œâ”€â”€ README.md                          â† you are here
â”œâ”€â”€ incident-reports/
â”‚   â””â”€â”€ case-01-bruteforce-exfiltration/
â”‚       â”œâ”€â”€ README.md
â”‚       â”œâ”€â”€ screenshots/
â”‚       â””â”€â”€ detection-rules/
â”‚           â””â”€â”€ sigma/                 â† SIEM-agnostic rules (Sigma YAML) for this case
â”‚
â”‚   (planned â€” added as the lab grows)
â”œâ”€â”€ architecture/                      â† topology diagrams
â”œâ”€â”€ playbooks/                         â† SANS PICERL response playbooks, one per case
â””â”€â”€ notes/                             â† lessons learned, infra troubleshooting logs
```

Detection rules live next to the incident they belong to, inside each case's own `detection-rules/` folder, rather than in one shared top-level folder â€” keeps every case self-contained.

## Roadmap

This lab is built incrementally rather than all at once â€” new attack scenarios, detection rules, and infrastructure keep getting added as the project grows. General directions being worked on:

- Automated containment (Wazuh Active Response) tied to specific detection rules
- Cortex enrichment wired into TheHive cases
- More Sigma rules as new detections are built
- A Windows Server + Sysmon host added to the lab
- Vulnerability scanning (OpenVAS/Nessus Essentials) against the lab

## Disclaimer

Every attack documented here was executed deliberately, in an isolated home lab, for educational and portfolio purposes. No machine, account, or piece of data involved belongs to a third party or a production environment. Any "sensitive" data referenced (e.g. `db_passwords.txt`) is fictitious, created specifically for these exercises.

