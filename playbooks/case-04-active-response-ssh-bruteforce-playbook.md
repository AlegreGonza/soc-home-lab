# Incident Response Playbook — Case 04: Active Response — Automated SSH Brute Force Containment

Format: SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), equivalent to NIST SP 800-61 (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity).

Full technical write-up: [`incident-reports/case-04-active-response-ssh-bruteforce/`](../incident-reports/case-04-active-response-ssh-bruteforce/)

---

## 1. Preparation

**Goal:** add automated, reversible containment (Wazuh Active Response `firewall-drop`) on top of the existing SSH brute-force rule (`100010`, Case 01) — a bounded 600-second IP block, not a permanent one.

**Assumption going in:** rule `100010` was already working (built and validated in Case 01). This assumption turned out to be false for the current host's OpenSSH version — the real preparation work ended up being re-establishing detection before containment could even be tested.

**Custom decoders:** `sshd-session-closed-invalid` / `sshd-session-closed-valid`, children of the native `sshd` decoder, required because OpenSSH 9.8+ (shipped with Ubuntu 24.04+) renamed its session-handling process to `sshd-session` and changed the auth-failure log format — the stock decoders never match it.

**Custom rules:** `100008`/`100009` (level 5, building blocks) and `100041` (level 10, correlation — 3+ failures/30s from the same source IP, recalibrated against OpenSSH's own `PerSourcePenalties` rate-limiting).

## 2. Identification

**Trigger (expected):** rule `100010` or `100041` fires on a burst of SSH authentication failures from the same source IP.

**Trigger (what actually happened first):** nothing fired. A live `hydra` attack produced zero brute-force alerts. `wazuh-logtest` against a real captured log line showed it decoding only against the generic `sshd` parent, matching a generic PAM rule (`2502`) instead of the SSH-specific chain — `srcip` was never extracted.

**Root cause:** OpenSSH 9.8+'s `sshd-session` log format (`Connection closed by invalid user X Y port Z [preauth]`) doesn't match any shipped Wazuh `sshd` child decoder, which all expect the classic `Failed password for...` line. This silently breaks the entire brute-force correlation chain (`5716` → `5760` → `100010`) with no error anywhere — confirmed against the official ruleset source and reported upstream as [wazuh/wazuh#39954](https://github.com/wazuh/wazuh/issues/39954).

**Re-establishing detection:** custom decoders + rules `100008`/`100009`/`100041` built and validated with `wazuh-logtest`, then live against a real `hydra` run, with the threshold recalibrated from `frequency=6` down to `frequency=3` to match OpenSSH's own connection-penalty pacing.

**Severity at triage: High** — a systemic detection blind spot affecting any Wazuh deployment monitoring a host with OpenSSH 9.8+, not a one-off misconfiguration.

## 3. Containment

- **Automated, via Wazuh Active Response:** `firewall-drop` bound to both `100010` (legacy) and `100041` (new format), `location: local` (executes on the agent), 600-second timeout, scoped to the specific attacking IP only — not host-wide, not permanent.
- **Validated live:** a real `hydra` attack was detected, correlated, and contained — confirmed via `iptables -L -n` showing the `DROP` rule for the attacker's IP, and a subsequent SSH connection attempt from Kali timing out while the block was active.
- **Evidence preservation:** export `rule.id: 100008, 100009, 100010, 100041` events and `/var/ossec/logs/active-responses.log` (on the **agent**, not the manager) before log rotation.

## 4. Eradication

- No persistent compromise occurred — this is a containment/detection-engineering case, not a breach. "Eradication" here means closing the detection gap itself: the custom decoder + rule set is the permanent fix until Wazuh's own ruleset covers OpenSSH 9.8+ natively.
- Two infrastructure issues had to be eradicated along the way before the fix could even take effect: a Docker bind-mount (`wazuh_manager.conf`) silently reverting any in-container `ossec.conf` edit on restart, and a missing `<expect>srcip</expect>` field in the Active Response command definition — both silent failures with no error output.

## 5. Recovery

- Full pipeline re-validated end-to-end after all four issues were fixed: attack → detect → correlate → `firewall-drop` → block → automatic unblock after the 600s timeout, confirmed independently in agent-side logs, `iptables`, and the Wazuh dashboard (`Host Unblocked by firewall-drop Active Response`, rule `652`).
- Legacy rule `100010` (classic OpenSSH format) was left in place but not re-validated against an older-OpenSSH host in this case — assumed still functional based on Case 01, not re-confirmed here.

## 6. Lessons Learned

- **The same native-decoder-vs-raw-log-format lesson from Case 02/03 recurred here, in a different layer.** There, the native Wazuh sudo decoder (`5402`) never matched raw `audisp-syslog` EXECVE records. Here, the native `sshd` decoders never match OpenSSH 9.8+'s `sshd-session` log lines. Same root pattern: a native decoder covers one specific format, and any format drift upstream breaks detection silently. The fix is the same each time — don't depend on the native decoder/`if_sid`; decode or match the raw log text directly.
- **A security control is not "done" when it's configured — only when it's validated end-to-end, live, with a real attack.** The Active Response binding itself was correct from the very first attempt; the entire rest of this case was proving that the thing it was bound to (detection) actually worked, which it didn't, silently.
- **Infrastructure issues can masquerade as detection-engineering issues.** The Docker bind-mount reverting `ossec.conf` looked, at first, like the Active Response binding itself was wrong — it wasn't; the binding never persisted long enough to take effect.
- **A finding with value beyond this one lab is worth reporting upstream.** The decoder gap affects any Wazuh deployment monitoring a host running OpenSSH 9.8+ — filed as [wazuh/wazuh#39954](https://github.com/wazuh/wazuh/issues/39954) with a full reproduction and a proposed fix, rather than kept as a private workaround.
