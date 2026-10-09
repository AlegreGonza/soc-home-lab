# Case 04: Active Response — Automated SSH Brute Force Containment

![Status](https://img.shields.io/badge/status-completed-brightgreen) ![Focus](https://img.shields.io/badge/focus-SOC%20Operations-blue) ![Platform](https://img.shields.io/badge/platform-Linux-orange) ![Telemetry](https://img.shields.io/badge/telemetry-Wazuh-lightgrey) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

---

> **Errata (2026-10-09).** The first version of this report, and of upstream issue [wazuh/wazuh#39954](https://github.com/wazuh/wazuh/issues/39954), claimed that the OpenSSH 9.8+ `sshd` → `sshd-session` split silently broke Wazuh's stock SSH brute-force detection chain. After a controlled reproduction, **that claim does not hold**. The `Failed password` lines decode correctly on `sshd-session` and reach the stock rules (5760 for real users, 5710 → 5712 for non-existent users). My custom rule `100010` never fired because it is bound to the 5760 branch, and the attack that triggered containment used a username OpenSSH logged as `invalid user`, which takes the 5710 → 5712 branch. I also misattributed rule 2502: it came from a PAM line, not from the `Failed password` line.
>
> What the reproduction **does** confirm is narrower: the stock decoders do not extract `srcip`/`srcuser` from `Connection closed by (invalid|authenticating) user <user> <ip> port <port> [preauth]` lines (they fall to rule 5722, level 0). That behavior is the same on OpenSSH 8.9p1 and 10.2p1, and on Wazuh 4.8.0 and 4.14.7, so it is **not** specific to OpenSSH 9.8+. Thanks to @xuxu298 for the review that prompted this. The sections below have been rewritten accordingly.

---

## Case at a Glance

| Field | Detail |
|---|---|
| **Victim host** | `ubuntu-victima` (192.168.1.46), Ubuntu 26.04 LTS, OpenSSH 10.2p1 Ubuntu-2ubuntu3.6 |
| **Attacker host** | Kali Linux (192.168.1.47), hydra 9.7 |
| **Severity** | Medium (containment exercise; the detection gap found is a coverage gap, not a total failure of brute-force detection) |
| **Goal** | Automated, reversible, scoped containment of SSH brute-force attacks via Wazuh Active Response |
| **Key finding** | The stock decoders do not extract `srcip`/`srcuser` from `Connection closed by ... user ... [preauth]` lines (rule 5722, level 0). Reproduced on Wazuh 4.8.0 and 4.14.7, with OpenSSH 8.9p1 and 10.2p1 |
| **Detections/response built** | 2 custom decoders, 3 custom rules (`100008`, `100009`, `100041`), 1 Active Response binding |
| **Public disclosure** | Reported upstream as [wazuh/wazuh#39954](https://github.com/wazuh/wazuh/issues/39954), corrected on 2026-10-09 after reproduction |
| **Related case** | Case 01 (original brute-force detection, rule `100010`). The native-decoder-vs-raw-log-format lesson from Cases 02/03 recurs here in a different form |

---

## Response Flow

```
hydra against a username OpenSSH logs as "invalid user"
(usuario_victima, 4 threads)
          │
          ├─► stock chain works: Failed password for invalid user → 5710 → 5712 (fires)
          │
          └─► custom rule 100010 is bound to the 5760 branch (real users only)
              → cannot fire for this run → Active Response bound to it never dispatches
                      │
                      ▼
        Connection closed by invalid user ... [preauth] is not decoded by stock (5722, level 0)
        → custom decoders + rules 100008 / 100009 / 100041 built for those lines
                      │
                      ▼
        Active Response still misfires: ossec.conf reset on restart (host bind-mount)
        → edited the host-side source file; added missing <expect>srcip</expect>
                      │
                      ▼
        CONFIRMED LIVE: attack → detect (100041) → firewall-drop → block
        → auto-unblock after 600 s timeout
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
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Incident Severity](#incident-severity)
10. [Response Actions](#response-actions)
11. [Detection & Response Rules](#detection--response-rules)
12. [Screenshots](#screenshots)
13. [Known Gaps / Pending Validation](#known-gaps--pending-validation)
14. [Final Conclusion](#final-conclusion)
15. [Skills Demonstrated](#skills-demonstrated)
16. [Disclaimer](#disclaimer)

---

## Overview

This case documents building automated, reversible containment for SSH brute-force attacks using Wazuh Active Response, and the troubleshooting required to make it work end to end. What started as a straightforward Active Response configuration (`firewall-drop` bound to the existing brute-force rule `100010`) turned into a diagnosis exercise: the rule never fired, the first explanation I proposed turned out to be wrong, and a controlled reproduction later showed the real picture. Along the way I found a genuine, narrower gap in the stock decoders (`Connection closed by ... user ... [preauth]` lines are not decoded) and a Docker bind-mount that silently reverted manual config changes.

## Scenario

- **Victim host**: `ubuntu-victima`, Ubuntu 26.04 LTS, OpenSSH 10.2p1 Ubuntu-2ubuntu3.6, IP `192.168.1.46`, registered as Wazuh agent `001`.
- **Attacker host**: Kali Linux, IP `192.168.1.47`, using `hydra` against SSH with a local wordlist (`passwords.txt`).
- **Wazuh manager**: Docker container (`single-node-wazuh.manager-1`, Wazuh 4.8.0), deployed via the official `wazuh-docker/single-node` docker-compose.
- **Starting condition**: existing brute-force detection rule (`100010`, from Case 01) assumed to be working; goal was to add automated containment on top of it.
- **The run that triggered containment** targeted the username `usuario_victima`, which OpenSSH logged as `invalid user` (confirmed from the raw `full_log` stored in the Wazuh indexer).

## Objectives

1. Configure Wazuh Active Response (`firewall-drop`) bound to the SSH brute-force rules, with a bounded, reversible timeout, not a permanent block.
2. Validate the full pipeline live, end to end, with a real attack, not just configuration review.
3. Diagnose and fix any gap found, and verify the diagnosis with a controlled reproduction before publishing it.
4. Document the containment design and the detection-engineering decisions behind it.
5. Report any upstream product gap found, with evidence, and correct the report when the evidence says so.

## Executive Summary

The Active Response configuration itself (`firewall-drop` bound to rule `100010`, scoped to the originating agent, 600-second timeout) was correct from the start. Live testing against it, however, showed that `100010` never dispatched anything.

My first diagnosis, published in this report and upstream, was that OpenSSH 9.8+ renamed its session process from `sshd` to `sshd-session` and that this broke the stock brute-force chain. A later reproduction showed that was wrong. The actual reason `100010` could not fire: it depends on `if_matched_sid 5760`, the branch for failed logins against **existing** users, while the run used a username that does not exist on the host. For non-existent users the stock chain is `Failed password for invalid user` → rule 5710 → rule 5712, and the stock rule 5712 ("brute force trying to get access to the system. Non existent user", level 10) did fire during the original runs, before any of my custom rules existed.

What the work did uncover is a narrower gap: `Connection closed by (invalid|authenticating) user <user> <ip> port <port> [preauth]` lines are not decoded by the stock sshd decoders (rule 5722, level 0, no `srcip`). Two custom decoders and two base rules extract `srcip`/`srcuser` from them, feeding a correlation rule (`100041`) calibrated against the pacing OpenSSH's own connection-penalty system allows an attacker. Once that detection path worked, the Active Response still did not fire, for two unrelated infrastructure reasons: the manager's `ossec.conf` is bind-mounted from a host file that the container re-copies on every restart (discarding in-container edits), and the `<command>` definition lacked `<expect>srcip</expect>`.

With those fixed, the full pipeline was confirmed live: a real `hydra` attack was detected (`100041`), contained (`iptables` DROP on the attacker IP, confirmed by a failed SSH attempt from Kali), and automatically reverted after the 600-second timeout (`Host Unblocked by firewall-drop Active Response`), verified in logs and in the Wazuh dashboard.

## Data Sources

| Source | What it provides |
|---|---|
| `/var/log/auth.log` (victim) | Raw SSH authentication events, ingested via Wazuh `<localfile>` |
| `wazuh-logtest` | Direct decoder/rule testing against real captured log lines, the primary diagnostic tool |
| Wazuh indexer (`Discover`, `full_log` field) | Raw log lines and the rules that fired during the original attack, used to re-check the first diagnosis |
| `/var/ossec/logs/active-responses.log` (**on the agent**, not the manager) | Ground truth for whether Active Response actually executed |
| `/var/ossec/logs/alerts/alerts.log` (manager) | Alert counts per rule ID, used to isolate detection vs. correlation vs. response failures |
| `iptables -L -n` (victim) | Ground truth for whether the containment action took effect |
| `docker inspect` | Revealed the host bind-mount responsible for `ossec.conf` silently reverting |
| Clean Wazuh containers + Ubuntu containers (2026-10-09) | Controlled reproduction with no local rules or decoders |

## Raw Event Timeline

| Step | Action | Outcome |
|---|---|---|
| 1 | Active Response configured, bound to rule `100010` | Config written, manager restarted |
| 2 | `hydra` launched against victim SSH using the username `usuario_victima` | Custom `100010` did not dispatch. In hindsight (Discover): stock 5710 fired for each `Failed password for invalid user` line, and stock 5712 fired during the same runs |
| 3 | `wazuh-logtest` against a PAM line (`PAM 4 more authentication failures ... rhost=192.168.1.47`) | Decoded only by the generic `sshd` parent decoder, rule `2502`. **Misread** at the time as proof that the whole chain was broken; the `Failed password` lines of the same run were decoding fine |
| 4 | Compared the stock decoders against the `Connection closed by ... user ...` lines | Those lines are not decoded (no `srcip`), a real but narrower gap |
| 5 | Built local decoders (`sshd-session-closed-invalid`/`-valid`) + base rules `100008`/`100009` | `wazuh-logtest` confirmed correct decoding and rule match |
| 6 | Built correlation rule `100041` (initially `frequency=6`, matching legacy `100010`) | Never reached threshold: OpenSSH's own connection-penalty system throttles `hydra` faster than 6 failures/20 s |
| 7 | Recalibrated to `frequency=4`, then `frequency=3`, timeframe `30s`, against real observed pacing | Rule `100041` fired correctly |
| 8 | Active Response still did not execute despite the alert firing | `active-responses.log` empty on the manager |
| 9 | Diagnosed: `location: local` logs to the **agent's** `active-responses.log`, not the manager's | Checked the correct file, still empty |
| 10 | Diagnosed: `ossec.conf` reset to its pre-edit state on every `docker restart` | `docker inspect` revealed a host bind-mount (`wazuh_manager.conf`) overwriting it |
| 11 | Edited the host-side source file instead of the in-container copy | `active-response` block persisted across restarts |
| 12 | Active Response still silently did not dispatch | Missing `<expect>srcip</expect>` in the `<command>` definition, added it |
| 13 | Full attack relaunched | `100041` fired at 19:36:55.162, `firewall-drop add` confirmed in the agent's `active-responses.log`, IP confirmed DROP'd in `iptables`, Kali SSH confirmed timing out |
| 14 | Waited for the 600 s timeout | `firewall-drop delete` confirmed in logs; IP removed from `iptables`; dashboard showed "Host Unblocked by firewall-drop Active Response" |
| 15 | Reported upstream | [wazuh/wazuh#39954](https://github.com/wazuh/wazuh/issues/39954) opened |
| 16 | A reviewer questioned the diagnosis; I reproduced it on clean containers (2026-10-09) | First diagnosis refuted, narrower gap confirmed; issue and this report corrected |

## Investigation

### What the original attack actually produced

Re-reading the stored alerts (Wazuh indexer, local time of the run) showed:

- `full_log` of the alerts is a raw `auth.log` line: `sshd-session[2142]: Failed password for invalid user usuario_victima from 192.168.1.47 port 56510 ssh2`. Wazuh decoded it with the stock `sshd` decoder (`data.srcip`, `data.srcuser` extracted) and fired **rule 5710** ("Attempt to login using a non-existent user"), 21 times in that run.
- **Stock rule 5712** (level 10, "brute force ... Non existent user") fired at 18:15:58, 18:38:58, 18:41:59 and 19:36:41, before any of my custom rules existed (the first custom rule alert, `100008`, appears at 18:39:10).
- My custom `100041` fired at 19:36:55.162, and "Host Blocked by firewall-drop" (rule 651) at 19:36:55.202. The unblock (rule 652) followed at 19:46:57, about 600 s later.
- With a real account and the classic `sshd` (Case 01, 2026-09-25), the same stock chain produced rule 5760 alerts.

So the stock ruleset was detecting this attack on the non-existent-user branch the whole time. The original custom rule `100010` was bound to the other branch.

### Reproduction on clean managers (2026-10-09)

To separate the variables, I built two throwaway Ubuntu containers (`ubuntu:22.04` with OpenSSH 8.9p1 and classic `sshd`; `ubuntu:26.04` with OpenSSH 10.2p1 and `sshd-session`), each with `rsyslog`, a real user (`victima`, confirmed with `id`) and a non-existent one (`fantasma`). One failed login with a bad password was made against each user, the raw lines were copied from `/var/log/auth.log`, and each line was passed **alone** through `wazuh-logtest` on clean `wazuh/wazuh-manager` containers (4.8.0 and 4.14.7) with **no local rules or decoders loaded**.

| Raw log line | Decoder / fields extracted | Rule |
|---|---|---|
| `Failed password for <real user> ...` | `sshd`, `dstuser` + `srcip` | **5760** |
| `Failed password for invalid user <x> ...` | `sshd`, `srcuser` + `srcip` | **5710** |
| `Connection closed by invalid user <x> <ip> port N [preauth]` | `sshd`, **no fields** | **5722** (level 0) |
| `Connection closed by authenticating user <x> <ip> port N [preauth]` | `sshd`, **no fields** | **5722** (level 0) |

The results were identical on all four combinations (Wazuh 4.8.0 / 4.14.7 × OpenSSH 8.9p1 / 10.2p1). The source address in the reproduction is the loopback `::1`, so the lines are structurally representative but not from a remote attacker.

Conclusions:

1. `sshd-session` is not the cause of anything: the `Failed password` lines decode and reach the stock rules in both process naming schemes.
2. The `Connection closed by ... user ... [preauth]` lines are already written by OpenSSH 8.9p1 in this form, so the gap is **not** tied to OpenSSH 9.8+.
3. A reviewer reading `0310-ssh_decoders.xml` on 4.14.7 reports that the stock `ssh-closed` decoder expects the shorter `by <ip> port` form, which is consistent with the behavior above. I verified the behavior with `wazuh-logtest`, not the decoder source.

### Building the fix: decoder + rules

The fix adds two decoders as children of the existing `sshd` parent decoder, extracting `srcuser`/`srcip`/`srcport` from the `Connection closed by ... user ...` lines, plus two base rules and a correlation rule. Full definitions in [Detection & Response Rules](#detection--response-rules).

A subtle bug surfaced while building this: a child decoder's matched name is **not** reported to downstream rules via `<decoded_as>` unless `<use_own_name>true</use_own_name>` is explicitly set. Without it, `wazuh-logtest` still shows the parent's name (`sshd`), and any rule relying on `<decoded_as>sshd-session-closed-invalid</decoded_as>` silently never matches even though the regex extraction works. This cost a full diagnostic cycle.

### Calibrating the correlation threshold against real attack pacing

The first version of rule `100041` reused the legacy threshold (`frequency=6`, `timeframe=20s`) from rule `100010`. It never fired. Comparing alert counts for the base rule (`100008`) before and after each attack run showed only 3-4 qualifying events landing within the window per `hydra` run, not 6. OpenSSH's own `PerSourcePenalties` rate limiting (visible in `auth.log` as `srclimit_penalise... activating ipv4 penalty`) throttles repeated connection attempts from the same source IP, so the attacker's pacing was slower than the correlation window assumed. The threshold was recalibrated to `frequency=3`, `timeframe=30s`, a deliberate trade-off between detection speed and a threshold that could never realistically be reached. (This only concerns the custom `Connection closed` path. The stock 5712 uses its own thresholds and fired earlier in the same runs.)

### The ossec.conf bind-mount trap

After confirming detection worked, the Active Response still never executed, and `/var/ossec/logs/active-responses.log` (checked on the **manager**) was empty. Two root causes were layered:

1. **Wrong log file.** With `<location>local</location>`, the Active Response executes and logs on the **agent** that generated the alert, not on the manager. This was the first false lead.
2. **Config not persisting.** Even after editing the manager's `ossec.conf` via `docker cp` and confirming it with `docker exec ... tail`, the Active Response block disappeared after every `docker restart`. `docker inspect single-node-wazuh.manager-1 --format "{{json .Mounts}}"` revealed a bind mount: `wazuh_manager.conf` on the Windows host is mounted to `/wazuh-config-mount/etc/ossec.conf`, and the container's entrypoint re-copies it over `/var/ossec/etc/ossec.conf` on every start, silently discarding any in-container edit. The fix was editing the host-side source file.

### The missing `<expect>` field

With the correct source file edited and persisting, the Active Response still did not dispatch: `wazuh-analysisd` logged a successful connection to the active-response queue but never wrote to it. The `<command>` definition was missing `<expect>srcip</expect>`, which tells `wazuh-execd` which field to extract from the alert and pass to the script. Without it, dispatch is silently skipped, with no error or warning. Adding it was the final fix.

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Tactic | Evidence | Confidence |
|---|---|---|---|---|---|
| Credential access | Brute Force: Password Guessing | T1110.001 | Credential Access | Stock rules `5710`/`5712` and custom rule `100041`, observed firing live against real `hydra` traffic | High |
| Response (defensive) | N/A (containment action, not an attacker technique) | — | — | Active Response `firewall-drop`, confirmed blocking and auto-reverting | High |

## Incident Severity

**Classification: Medium.**

Rationale: this is a containment exercise against a lab attacker. The detection gap found (`Connection closed by ... user ... [preauth]` lines are not decoded) reduces visibility and removes one correlation path, but it is not a failure of SSH brute-force detection as a whole: the `Failed password` lines already feed the stock rules. The secondary operational finding, a Docker bind-mount silently discarding manual config changes, is worth documenting for anyone running the official `wazuh-docker` compose files.

*(The first version of this report classified this case as High on the strength of the incorrect "silent detection failure" diagnosis.)*

## Response Actions

1. **Detection**: custom decoders + rules built to cover the `Connection closed by ... user ...` lines (`100008`, `100009`, `100041`), adding visibility and a second correlation path.
2. **Containment**: Wazuh Active Response (`firewall-drop`), scoped to the originating agent (`location: local`), bound to the legacy (`100010`) and new (`100041`) brute-force rules, with a 600-second timeout. Automated, reversible, and narrowly targeted at the attacking IP only.
3. **Validation**: full pipeline confirmed live end to end (attack, detection, correlation, block, automatic unblock), independently verified via agent-side logs, `iptables`, and the Wazuh dashboard.
4. **Upstream reporting**: the decoder gap was reported to the Wazuh project ([#39954](https://github.com/wazuh/wazuh/issues/39954)). After a reviewer questioned the diagnosis, I reproduced it on clean containers, retracted the parts that did not hold, and narrowed the issue to what the evidence supports.
5. **Operational note for future deployments**: any manual `ossec.conf` edit on this lab's manager must go through the host-side `wazuh_manager.conf` file, not `docker cp` into the running container, or it will be silently discarded on the next restart.

## Detection & Response Rules

**Local decoders** (`/var/ossec/etc/decoders/local_decoder.xml`):

```xml
<decoder name="sshd-session-closed-invalid">
  <parent>sshd</parent>
  <use_own_name>true</use_own_name>
  <prematch>^Connection closed by invalid user </prematch>
  <regex offset="after_prematch">^(\S+) (\S+) port (\d+)</regex>
  <order>srcuser, srcip, srcport</order>
</decoder>

<decoder name="sshd-session-closed-valid">
  <parent>sshd</parent>
  <use_own_name>true</use_own_name>
  <prematch>^Connection closed by authenticating user </prematch>
  <regex offset="after_prematch">^(\S+) (\S+) port (\d+)</regex>
  <order>srcuser, srcip, srcport</order>
</decoder>
```

**Local rules** (`/var/ossec/etc/rules/local_rules.xml`):

```xml
<group name="local,syslog,sshd,">

  <rule id="100008" level="5">
    <decoded_as>sshd-session-closed-invalid</decoded_as>
    <description>sshd: authentication failed for invalid user $(srcuser) from $(srcip) (new OpenSSH format)</description>
    <group>authentication_failed,ssh_auth_fail_new,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100009" level="5">
    <decoded_as>sshd-session-closed-valid</decoded_as>
    <description>sshd: authentication failed for user $(srcuser) from $(srcip) (new OpenSSH format)</description>
    <group>authentication_failed,ssh_auth_fail_new,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

</group>

<group name="local,syslog,sshd,">

  <rule id="100010" level="10" frequency="6" timeframe="20" ignore="180">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>sshd: Possible brute force attack. 6 or more failed logins from the same source IP within 20 seconds.</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <rule id="100041" level="10" frequency="3" timeframe="30" ignore="180">
    <if_matched_group>ssh_auth_fail_new</if_matched_group>
    <same_source_ip />
    <description>sshd: Possible brute force attack (new OpenSSH format). 3 or more failed logins from the same source IP within 30 seconds.</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

</group>
```

Notes on these rules:

- `100010` hangs off `5760`, the branch for failed logins against **existing** users. It does not see attempts against non-existent users, which take `5710` → `5712`.
- The "(new OpenSSH format)" labels in the `100008`/`100009`/`100041` descriptions are historical: the `Connection closed by ... user ...` format is also written by OpenSSH 8.9p1, so the label is misleading and could be renamed.

**Active Response** (host-side `wazuh_manager.conf`, not edited directly in-container, see Investigation):

```xml
<command>
  <name>firewall-drop-ssh-bruteforce</name>
  <executable>firewall-drop</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop-ssh-bruteforce</command>
  <location>local</location>
  <rules_id>100010,100041</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Live confirmation** (agent-side `/var/ossec/logs/active-responses.log`):

```
2026/10/04 22:36:55 active-response/bin/firewall-drop: Starting
2026/10/04 22:36:55 active-response/bin/firewall-drop: {"command":"add", ... "rule":{"id":"100041", ...}, "data":{"srcip":"192.168.1.47", ...}}
2026/10/04 22:36:55 active-response/bin/firewall-drop: Ended
```

`iptables -L -n` on the agent confirmed the DROP rule for `192.168.1.47` was added, and a subsequent `ssh` attempt from the attacker host timed out while the block was active. After the 600 s timeout, the Wazuh dashboard logged **"Host Unblocked by firewall-drop Active Response"** (rule `652`), and the `iptables` rule was confirmed removed.

## Screenshots

**`iptables` DROP rule confirmed on the agent**, with both bound rules (`100010`, `100041`) triggering the same Active Response and producing two `DROP` entries for `192.168.1.47`:

![iptables DROP confirmed](screenshots/caso-04-iptables-drop-confirmed-1.png)
![iptables DROP confirmed](screenshots/caso-04-iptables-drop-confirmed-2.png)

**Automatic unblock after the 600 s timeout**, confirmed in the Wazuh dashboard (`Discover`):

![Host Unblocked by firewall-drop Active Response](screenshots/caso-04-wazuh-dashboard-unblocked.png)

## Known Gaps / Pending Validation

- **Upstream issue** [#39954](https://github.com/wazuh/wazuh/issues/39954) is open and has been narrowed to the `Connection closed by ... user ... [preauth]` gap. A follow-up Pull Request integrating the fix into `0310-ssh_decoders.xml` is still planned.
- **Not tested in the reproduction**: OpenSSH versions other than 8.9p1 and 10.2p1; a full replay of the attack against a clean manager (only per-line `wazuh-logtest`); sources other than loopback `::1`.
- **Untested improvement**: binding the Active Response to the stock rule `5712` (non-existent users) and/or `5760`-branch rules in addition to `100010`/`100041`, so containment does not depend on the custom `Connection closed` decoders.
- **`frequency=3` on rule `100041`** is tuned to this lab's observed OpenSSH penalty pacing. A production deployment should re-validate it against its own environment.
- **Legacy rule `100010`** was left in place but not re-validated against a host running older OpenSSH in this case. It is assumed functional for existing-user attacks based on Case 01 (rule 5760 alerts observed on 2026-09-25).

## Final Conclusion

This case started as a routine Active Response configuration task. Its most useful outcome turned out to be a correction. My first explanation for why the brute-force rule did not fire (a supposed OpenSSH 9.8+ log-format break) was published and was wrong: the rule was bound to the wrong branch of the stock chain for the test I ran. A reviewer questioned it, I reproduced the behavior on clean containers across two Wazuh versions and two OpenSSH versions, and retracted what did not hold. What the evidence does support is a narrower gap: the `Connection closed by ... user ... [preauth]` lines are not decoded by the stock sshd decoders. Two infrastructure issues (a Docker bind-mount reverting config, a missing `<expect>` field) also had to be found and fixed before the pipeline could be validated live, and that end-to-end validation, attack, detect, correlate, block, auto-unblock, holds as documented.

## Skills Demonstrated

- Root-causing a silent failure through systematic isolation (hydra → decoder → rule → correlation → dispatch → execution), rather than assuming the most recently configured piece was at fault
- Direct use of `wazuh-logtest` as the primary diagnostic tool, including per-line tests on clean containers with no local rules
- Re-checking a published diagnosis against stored raw evidence (indexer `full_log`, rule IDs, timestamps) instead of memory
- Controlled reproduction: isolating one variable at a time (existing vs. non-existent user, classic `sshd` vs. `sshd-session`, Wazuh 4.8.0 vs. 4.14.7) and recording what was *not* tested
- Publicly correcting an upstream issue and this report when the evidence contradicted the original claim
- Recognizing and working around undocumented Wazuh behavior (`<use_own_name>`, `<expect>`) through controlled, reproducible testing
- Calibrating a detection threshold against observed attacker-side constraints (OpenSSH's own rate limiting) instead of an assumed default
- Diagnosing a Docker/infrastructure issue (bind-mount overwrite) that masked a configuration problem as a detection problem
- End-to-end validation discipline: confirming detection, correlation, response, and reversal independently, in logs and in the product UI

## Disclaimer

This is a **real, deliberately executed** containment exercise in an isolated home lab, for educational and portfolio purposes. None of the machines or data involved belong to a third party or a production environment. All attack traffic was generated against infrastructure owned and controlled by the author. The upstream issue ([#39954](https://github.com/wazuh/wazuh/issues/39954)) concerns a ruleset/decoder coverage gap, not a security vulnerability in Wazuh itself, and was filed through the public Issues tracker per Wazuh's own security policy, which reserves private disclosure for vulnerabilities that could compromise Wazuh itself.
