# Incident Response Playbook — Case 01: SSH Brute Force + Data Exfiltration

Format: SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), equivalent to NIST SP 800-61 (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity).

Full technical write-up: [`incident-reports/case-01-bruteforce-exfiltration/`](../incident-reports/case-01-bruteforce-exfiltration/)

---

## 1. Preparation

**Telemetry in place before this incident:**
- Suricata (NIDS) on the victim host, flagging anomalous traffic (port scans, brute-force patterns) at the network level.
- Wazuh agent (HIDS) on the victim host: native PAM/sshd decoders, File Integrity Monitoring (FIM) on sensitive directories.
- Custom Wazuh rule `100010`: 6+ SSH login failures from the same source IP within 20 seconds — built to catch automated brute-force tools faster than the native rule (`5763`, 8 failures/120s).
- Wazuh → TheHive integration: high-confidence alerts (rule `100010`) auto-promote to a Case, skipping manual triage.

**Assumed baseline:** a single victim user (`victima`) with normal interactive SSH access; no automated login attempts expected from outside the lab network.

## 2. Identification

**Trigger:** Suricata flags a SYN scan ("Possible port scan", rule `86601`) against the victim host at 17:04:46 — first sign of hostile activity.

**Confirmation:** within the next ~90 seconds, repeated SSH authentication failures from the same source IP cross three independent detection layers: Suricata's own brute-force signature, Wazuh's native PAM rule (level 10), and the custom rule `100010` (level 10, fires on the 6th failure).

**Scoping the incident:** correlating `sudo`-logged commands (rule `5402`) and `sshd: authentication success` events (rule `5715`) by timestamp shows the attacker gained valid access, browsed the filesystem (`sudo ls -la backup_sistema/`), and opened multiple short SSH sessions — consistent with discrete actions (login, transfer, cleanup) rather than one long session.

**What was NOT directly observable:** the actual `scp` exfiltration (encrypted SSH/SCP traffic hides content and intent from both NIDS and application logs) and any file browsing done without `sudo` — both documented as blind spots in the case report.

**Severity at triage: High** — valid access gained via a weak, guessable password (`victima:victima`), with inferred exfiltration of a credentials file.

## 3. Containment

- **Immediate:** block the attacker's source IP at the firewall / Wazuh Active Response level on `rule.id: 100010` (reversible, low-risk — pending implementation, see Case 01 roadmap item in the main project tracker).
- **Account-level:** force-terminate any active sessions for `victima` originating from the attacker IP.
- **Evidence preservation:** export Wazuh events `rule.id: 86601, 2502, 100010, 5715, 5402, 553` and the TheHive Case/Alert record before any log rotation.

## 4. Eradication

- Force a password change on the `victima` account — the root cause is a password identical to the username, not a vulnerability in SSH itself.
- Fix permissions on `/home/victima/.backup_sistema` (775 → 750 or more restrictive) — the sensitive file itself had correct permissions (600), but the containing folder did not.
- Threat-hunt for other accounts on the same host (or others in scope) with an equally weak, guessable password pattern (`user:user`).

## 5. Recovery

- Confirm no other sensitive files remain exposed under the same or similarly permissioned directories.
- Restore `db_passwords.txt` from backup if the exercise required operational continuity (lab-only; no production impact).
- Re-enable normal SSH access for `victima` only after the password has been rotated and verified against a basic strength check.

## 6. Lessons Learned

- **Detection worked across independent layers** for the brute-force phase (NIDS + two HIDS rules), giving redundancy even if one layer is tuned out or disabled.
- **FIM acted as an independent safety net** for the anti-forensics step (file deletion) — a layer completely separate from the authentication-log pipeline that caught everything else, demonstrating the value of defense in depth.
- **Two confirmed blind spots, tracked as future work rather than hidden:**
  1. Commands run without `sudo` leave no trace in the current command-audit pipeline.
  2. Encrypted SSH/SCP traffic hides the content and nature of a file transfer from both NIDS and application logs.
- **Process gap identified independent of this specific attack:** no automated containment exists yet for a confirmed brute-force source IP — the detection-to-containment loop is still manual. This is now tracked as a concrete next step (Wazuh Active Response tied to `rule.id: 100010`).
