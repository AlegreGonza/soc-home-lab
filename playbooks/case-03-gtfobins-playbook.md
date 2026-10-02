# Incident Response Playbook — Case 03: Privilege Escalation — GTFOBins Abuse of a Restricted Sudo Binary

Format: SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), equivalent to NIST SP 800-61 (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity).

Full technical write-up: [`incident-reports/case-03-gtfobins/`](../incident-reports/case-03-gtfobins/)

---

## 1. Preparation

**Telemetry reused from Case 02, unchanged:** the `auditd → audisp-syslog → Wazuh` pipeline built for Case 02 already captures any `sudo`-invoked command's full arguments, regardless of which binary is called — no infrastructure changes were needed for this case.

**Custom Wazuh rule:** `100040` (level 13) — flags a sudo-authorized binary spawning a shell (the GTFOBins shell-escape pattern), as a standalone `pcre2` match against the raw EXECVE text. Same log-format lesson as Case 02's rule `100031` applies here: the native sudo decoder (`5402`) never fires on raw `audisp-syslog` EXECVE records, so no detection on this pipeline can depend on `if_sid`.

**Baseline assumption at the time:** a new account (`operador`) is granted `sudo` access scoped to a single binary (`find`) — intended as a least-privilege configuration, not a broad grant like Case 02's.

## 2. Identification

**Trigger:** rule `100031` (reused, unmodified from Case 02) fires on `sudo -l` recon, confirming `operador`'s grant is scoped to the one binary as configured — low severity, individually ambiguous.

**Escalation:** `sudo find . -exec /bin/sh \; -quit` fires rule `100040` (level 13, critical) in the same second as the native `5402` "Successful sudo to ROOT executed" event — a shell spawned via a sudo-authorized binary's own `-exec` feature.

**Confirming full compromise:** terminal evidence (`whoami` → `root`, `id` → `uid=0(root) gid=0(root) groups=0(root)`) confirms this is not a partial privilege but a complete, unrestricted root session.

**Scoping the incident:** reviewing the `sudoers` entry shows it was correctly scoped to one binary, not `ALL` — the root cause is not an overly broad grant (as in Case 02) but an unvetted one: the specific binary's own functionality was never checked against known escalation primitives before the grant was approved.

**Severity at triage: Critical** — full root compromise of the host, from a configuration that looked safe on file inspection alone.

## 3. Containment

- Revoke the `operador` sudoers entry for `find` immediately.
- Terminate any active sessions for the account.
- **Evidence preservation:** export `rule.id: 100031, 100040` events and the raw `auditd`/`audisp-syslog` records before log rotation.

## 4. Eradication

- Audit every `sudoers` entry that grants a single binary across the host — cross-reference each one against [GTFOBins](https://gtfobins.github.io/) before considering it safe. Scoping to a binary name is not the same as scoping to a safe capability set.
- Cross-check this specific finding against Case 02: both cases are the same underlying failure mode (sudo grant → unintended root access), just with different root causes — Case 02 was a grant that was too broad by design, Case 03 is a grant that was correctly scoped but still exploitable via the binary's own features.

## 5. Recovery

- Review what the `operador` account accessed during the root session. In this lab exercise no changes were made, but a real incident would require a full filesystem and persistence-mechanism review following any confirmed root compromise, before re-enabling any access for the account.
- Re-grant `operador` access (if still needed) only after replacing the `find` grant with either no sudo access, or a binary confirmed to have no GTFOBins escalation primitive for the required use case.

## 6. Lessons Learned

- **A single-binary `sudo` grant is not, by itself, a least-privilege control.** It only moves the question to whether that specific binary has a documented escalation primitive — `find`'s `-exec` flag is one of dozens cataloged by GTFOBins for exactly this purpose.
- **A well-built, binary-agnostic detection pipeline pays off across unrelated attack techniques.** The hard engineering work done in Case 02 (capturing full `sudo` command-line arguments, independent of `sudo`'s own logging) needed zero changes to detect a structurally different exploitation pattern here.
- **The `if_sid`/log-format mismatch from Case 02 recurred and was root-caused faster the second time** — evidence that documenting a root cause (not just the fix) pays off on the next, unrelated incident that happens to share the same underlying log-pipeline quirk.
- **Policy gap identified, now tracked as a post-incident action:** formalize that any new single-binary `sudoers` grant is checked against GTFOBins before approval, not just reviewed for nominal scope.
