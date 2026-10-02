# Incident Response Playbook — Case 02: Sudo Abuse — Credential Dumping via Misconfigured Grant

Format: SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), equivalent to NIST SP 800-61 (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity).

Full technical write-up: [`incident-reports/case-02-sudo-credential-dumping/`](../incident-reports/case-02-sudo-credential-dumping/)

---

## 1. Preparation

**Telemetry built specifically for this case:** this host runs `sudo-rs` (the Rust reimplementation of sudo), whose own logging (`/var/log/auth.log`) was insufficient to reliably capture full command-line arguments for correlation. A custom `auditd` execve watch on `/usr/lib/cargo/bin/sudo` (the real `sudo-rs` binary path — the wrong path silently produces zero events) was built and made persistent, forwarding records via `audisp-syslog` into `/var/log/syslog`, already ingested by Wazuh's existing `syslog`-format `localfile`.

**Custom Wazuh rules:**
- `100031` (level 3): flags `sudo -l` privilege-enumeration recon, as a standalone `pcre2` match against the raw EXECVE text (no `if_sid` dependency — the native sudo decoder `5402` only covers the `auth.log`-format line, never the raw `audisp-syslog` EXECVE record).
- `100030` (level 12): flags a sudo-elevated read of `/etc/shadow` or `/etc/passwd`.
- `100033` (level 13): correlates `100031` followed by `100030` within a 300-second window into a single high-confidence alert.

**Baseline assumption at the time:** `victima` holds a `sudo` grant intended for routine administrative file access — the grant's actual scope (broad enough to read any file as root) had not yet been audited.

## 2. Identification

**Trigger:** rule `100031` fires on `sudo -l`, logged at low severity (level 3) — individually ambiguous, since legitimate admins also check their own privileges.

**Escalation:** within the correlation window, `sudo cat /etc/shadow` fires rule `100030` (level 12) — a credential-file read via sudo. The two events together fire the correlation rule `100033` (level 13, critical), because the composite pattern — recon immediately followed by credential access — is high-confidence even though neither event alone is.

**Scoping the incident:** confirming the `sudoers` entry for `victima` shows a grant broad enough to read any file as root, not scoped to any specific legitimate need — the actual root cause, not just the symptom (the shadow-file read).

**Severity at triage: Critical** — the dumped file exposes every local account's password hash for offline cracking, from a single, specific `sudo` misconfiguration with system-wide impact.

## 3. Containment

- **Reversible, not full isolation:** revoke the specific `sudo` grant for `victima` and force session termination — a credential-dumping event can indicate the account itself is compromised and warrants root-cause investigation, not automatic full host isolation at Tier 1.
- **Escalate to IR team** given the severity and the system-wide blast radius of a shadow-file dump.
- **Evidence preservation:** export `rule.id: 100030, 100031, 100033` events and the raw `auditd`/`audisp-syslog` records before log rotation.

## 4. Eradication

- Audit and tighten the `sudoers` grant for `victima` — scope file-read access explicitly (e.g. to a specific directory or command), rather than granting broad `sudo` rights.
- Extend the same audit to every other account on the host: any `sudoers` entry broad enough to read arbitrary files as root is the same class of misconfiguration, regardless of which account triggered this specific incident.

## 5. Recovery

- Rotate **all** local account passwords — the `/etc/shadow` dump must be treated as if every hash is now subject to offline cracking, regardless of individual password strength. This is a host-wide action, not scoped to the one compromised account.
- Re-enable `victima`'s access only with the corrected, scoped `sudoers` entry in place.

## 6. Lessons Learned

- **A `sudo` grant intended for convenience is a privilege-escalation path if not explicitly scoped** — "broad but intended for one task" and "unrestricted root" have the same practical blast radius once the grant exists.
- **Engine-level bugs can silently break detection and need to be root-caused, not worked around:** a literal double-quote character inside a `<match type="pcre2">` block caused rule `100031` to silently fail to match for an extended period, even escaped — the fix (avoiding quote characters, matching unquoted positional substrings) is now a documented pattern reused in later cases on this host.
- **A non-default `sudo` implementation changes how it has to be audited:** `sudo-rs`'s binary path (`/usr/lib/cargo/bin/sudo`) differs from the classic C sudo path assumed by most auditd examples — auditing the wrong path produces a pipeline that looks correctly configured but silently captures nothing.
- **Formalize a `sudoers` review process** for any grant broad enough to read arbitrary files, as a standing control rather than a reactive one-off fix — tracked as a post-incident action.
