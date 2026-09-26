# Sigma Detection Rules

SIEM-agnostic detection logic for this lab, written in [Sigma](https://github.com/SigmaHQ/sigma) format before being translated into native Wazuh rules. The idea: write the detection logic once, in a portable format, then convert it to whatever SIEM syntax the lab is currently using (today Wazuh; potentially Elastic, Splunk, etc. later) with `sigma-cli` / pySigma.

## Workflow going forward

1. Draft new detections here first, as Sigma YAML.
2. Validate the logic conceptually (does the `detection` block actually express the behavior we want to catch?).
3. Convert / hand-translate to the native syntax of the SIEM in use (Wazuh XML rules for now).
4. Test the native rule (`wazuh-logtest` for Wazuh) before deploying.
5. Keep both versions in the repo, cross-referenced (see each rule's "Native mapping notes" section).

## Rules in this folder

| File | Covers | MITRE ATT&CK | Native Wazuh rule |
|---|---|---|---|
| `ssh_bruteforce_t1110_001.yml` | SSH brute force (6+ failed logins/20s, same source IP) | T1110.001 | Custom rule `100010` |
| `sensitive_file_deletion_t1070_004.yml` | Deletion of a file inside a monitored/sensitive directory (FIM) | T1070.004 | Native rule `553` (syscheck) |

Both rules are documented in detail, with real evidence, in [`incident-reports/case-01-bruteforce-exfiltration/`](../../incident-reports/case-01-bruteforce-exfiltration/).
