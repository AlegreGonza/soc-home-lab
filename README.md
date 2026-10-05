# SOC Home Lab — Suricata + Wazuh + TheHive + Cortex

![Status](https://img.shields.io/badge/status-in%20progress-yellow) ![Focus](https://img.shields.io/badge/focus-SOC%20Tier%201-blue) ![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20Docker-orange) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

A self-built detection and incident-response lab, put together to learn and demonstrate real SOC Tier 1 skills: not tutorials with pre-made datasets, but live attacks executed against real machines, detected, investigated, and documented end to end.

This repo is a **work in progress**. It grows one use case at a time — each new attack scenario adds its own detection rules, its own investigation, and its own write-up. Nothing here is a finished product; it's a running log of a SOC analyst learning by building.

---

## Incident cases

| # | Case | MITRE ATT&CK | Status |
|---|---|---|---|
| 01 | [SSH Brute Force + Data Exfiltration](incident-reports/case-01-bruteforce-exfiltration/) | T1595 · T1110.001 · T1078.003 · T1083 · T1005 · T1048.002 · T1070.004 | ✅ Completed |
| 02 | [Sudo Abuse — Credential Dumping](incident-reports/case-02-sudo-credential-dumping/) | T1069.001 · T1548.003 · T1003.008 | ✅ Completed |
| 03 | [Privilege Escalation — GTFOBins Abuse of a Restricted Sudo Binary](incident-reports/case-03-gtfobins/) | T1069.001 · T1548.003 · T1059.004 | ✅ Completed |
| 04 | [Active Response — Automated SSH Brute Force Containment](incident-reports/case-04-active-response-ssh-bruteforce/) | T1110.001 | ✅ Completed |

> Note: the port-scan scenario originally numbered "02" is already fully covered inside Case 01's own report (reconnaissance phase), so it doesn't get a separate entry.

---

## Why this project exists

The goal is a first job as a **SOC Tier 1 Analyst**. Instead of collecting certificates first and building later, this lab flips that order: every skill (log correlation, detection engineering, incident documentation, SOAR automation) is learned by solving a real problem that came up while building or attacking this environment — including the infrastructure failures along the way, which turned into some of the best material here (see the troubleshooting notes inside each case).

## Architecture

```
                    ┌─────────────────────────┐
                    │   Kali Linux (Attacker)  │
                    │      192.168.1.47        │
                    └────────────┬─────────────┘
                                 │ attacks (nmap, Hydra, ssh, scp...)
                                 ▼
                    ┌─────────────────────────┐
                    │  Ubuntu Server (Victim)  │
                    │      192.168.1.46        │
                    │  Suricata (NIDS)          │
                    │  Wazuh Agent (HIDS/FIM)   │
                    └────────────┬─────────────┘
                                 │ logs / alerts
                                 ▼
                    ┌─────────────────────────┐
                    │   Wazuh Manager (Docker) │
                    │   Windows host           │
                    │   SIEM + correlation      │
                    └────────────┬─────────────┘
                                 │ high-confidence alerts
                                 │ (Wazuh → TheHive integration)
                                 ▼
                    ┌─────────────────────────┐
                    │  TheHive + Cortex (VM)   │
                    │     192.168.1.49         │
                    │  Case management + SOAR  │
                    │  enrichment (Docker)     │
                    └─────────────────────────┘
```

| Host | Role | Stack |
|---|---|---|
| Kali Linux (`192.168.1.47`) | Attacker | nmap, Hydra, ssh/scp |
| Ubuntu Server (`192.168.1.46`) | Victim | Suricata (NIDS), Wazuh agent (HIDS/FIM) |
| Windows PC (Docker) | Wazuh Manager | `wazuh-docker/single-node`, SIEM + correlation engine |
| VM (`192.168.1.49`) | SOAR | TheHive (case management), Cortex (enrichment), Elasticsearch |

Each attack scenario is executed live against a real machine, detected in real time, then investigated and written up — not built backwards from a synthetic dataset. Every write-up follows a consistent format: scenario, timeline of raw events, investigation narrative, IOCs, IOAs, MITRE ATT&CK mapping, severity, response actions, the detection rule(s) involved, and skills demonstrated. New scenarios get added over time as the lab grows.

## Data Sources & Log Telemetry

Where every detection in this lab actually gets its evidence from — no case is "detected by Wazuh" in the abstract, each one depends on a specific log source reaching the manager.

| Source | Where it lives | What it captures | Used in |
|---|---|---|---|
| Suricata `eve.json` | Victim host (`/var/log/suricata/eve.json`) | Network-level NIDS alerts: port scans, SSH brute-force traffic patterns | Case 01 |
| `auth.log` (native Wazuh decoders) | Victim host, ingested by the Wazuh agent | sshd authentication success/failure, PAM session open/close, the native sudo decoder (`5402`) for the human-readable `sudo` log line | Case 01, 02, 03 |
| `auditd` → `audisp-syslog` → `/var/log/syslog` (custom pipeline) | Victim host, ingested by the Wazuh agent's existing `syslog`-format `localfile` | Full command-line arguments for every `sudo`-invoked process, as raw `type=EXECVE` records — built specifically because `auth.log` (and `sudo-rs`'s own logging) doesn't capture enough detail to correlate by exact command | Case 02, 03 |
| Wazuh FIM (`syscheck`) | Victim host, Wazuh agent, realtime | File creation/deletion/modification on watched directories, independent of command-level auditing | Case 01 |
| Wazuh manager (correlation engine) | Docker container on the Windows PC | Runs all native + custom detection rules against the sources above, generates alerts | All cases |
| TheHive / Cortex | Separate VM (`192.168.1.49`) | Case management, alert correlation, SOAR enrichment for high-confidence Wazuh alerts | All cases, via the Wazuh → TheHive integration |

**Why two different `sudo` log paths exist (`auth.log` vs. the `auditd` pipeline):** the native `auth.log` line is enough to know *that* `sudo` ran and *who* ran it (rule `5402`), but not the exact arguments — good enough for Case 01's discovery step, not precise enough to correlate on in Case 02/03. The custom `auditd`/`audisp-syslog` pipeline was built once, in Case 02, specifically to close that gap, and reused unchanged in Case 03.

## What's already working

- **Network + host detection**: Suricata (NIDS) and Wazuh (HIDS/SIEM), correlating alerts from both layers.
- **File Integrity Monitoring (FIM)**: realtime watch on sensitive directories, independent of command-level auditing.
- **Custom detection rules**: purpose-built Wazuh rules for SSH brute-force (Case 01), sudo credential dumping (Case 02), GTFOBins-style shell escapes (Case 03), and OpenSSH 9.8+ brute-force detection (Case 04), each validated with `wazuh-logtest` and live traffic.
- **Automated containment**: Wazuh Active Response (`firewall-drop`) bound to the SSH brute-force rules, scoped to the attacking IP with a 600-second timeout — confirmed live end-to-end, including the automatic unblock (Case 04).
- **SOAR automation**: a Wazuh → TheHive integration that auto-promotes high-confidence alerts straight to a Case, skipping manual triage.
- **SIEM-agnostic detection logic**: new detections are drafted first in [Sigma](https://github.com/SigmaHQ/sigma) format, then converted to native Wazuh syntax. Each case keeps its own `detection-rules/` folder alongside its report.

## Documented blind spots

Part of the value of this lab is being honest about what the current stack does **not** catch:
- Commands run without `sudo` leave no trace in the command-audit pipeline.
- Encrypted SSH/SCP traffic hides the content and nature of a file transfer from both NIDS and application logs.

These are tracked as future work rather than hidden — see each case's own report for details.

## Repository structure

```
soc-home-lab/
├── README.md                              ← you are here
├── incident-reports/
│   ├── case-01-bruteforce-exfiltration/
│   │   ├── README.md
│   │   ├── screenshots/
│   │   └── detection-rules/
│   │       └── sigma/                     ← SIEM-agnostic rules (Sigma YAML) for this case
│   ├── case-02-sudo-credential-dumping/
│   │   ├── README.md
│   │   ├── screenshots/
│   │   └── detection-rules/
│   │       └── sigma/
│   ├── case-03-gtfobins/
│   │   ├── README.md
│   │   ├── screenshots/
│   │   └── detection-rules/
│   │       └── sigma/
│   └── case-04-active-response-ssh-bruteforce/
│       ├── README.md
│       ├── screenshots/
│       └── detection-rules/
│           └── sigma/
├── architecture/                          ← topology diagrams
├── playbooks/                             ← SANS PICERL response playbooks, one per case
└── notes/                                 ← lessons learned, infra troubleshooting logs
```

Detection rules live next to the incident they belong to, inside each case's own `detection-rules/` folder, rather than in one shared top-level folder — keeps every case self-contained.

## Roadmap

This lab is built incrementally rather than all at once — new attack scenarios, detection rules, and infrastructure keep getting added as the project grows. General directions being worked on:

- Cortex enrichment wired into TheHive cases
- More Sigma rules as new detections are built
- A Windows Server + Sysmon host added to the lab
- Vulnerability scanning (OpenVAS/Nessus Essentials) against the lab

## Disclaimer

Every attack documented here was executed deliberately, in an isolated home lab, for educational and portfolio purposes. No machine, account, or piece of data involved belongs to a third party or a production environment. Any "sensitive" data referenced (e.g. `db_passwords.txt`) is fictitious, created specifically for these exercises.
