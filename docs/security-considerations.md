# Security Considerations & Defense-in-Depth Analysis

File Integrity Monitoring (FIM) is a foundational control in frameworks like **PCI-DSS (Requirement 11.5)**, **NIST SP 800-53 (SI-7)**, and **ISO/IEC 27001 (A.12.2)**. However, implementing FIM on Linux requires deep consideration of adversarial tampering, privilege boundaries, and file system mechanics.

---

## 1. Protecting the Baseline Integrity

A critical question asked during SOC and security engineering interviews:  
> *"If an attacker gains root access, what prevents them from simply modifying the FIM baseline to authorize their malicious files?"*

Our utility implements layered controls to mitigate baseline poisoning:

### 1.1 Deterministic Catalog Checksum
The baseline includes an aggregate cryptographic signature (`catalog_checksum`) generated over the deterministically sorted file records:
```python
canonical_json = json.dumps(files_dict, sort_keys=True, separators=(",", ":"))
return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
```
If an adversary opens `baseline.json` in an editor and swaps a hash for `/bin/login`, the catalog checksum validation fails during `main.py scan`, immediately raising a high-priority tampering alert.

### 1.2 Read-Only & Immutable Storage Strategies
In production hardening:
- **Linux Extended Attributes**: Set the immutable bit on the baseline file:
  ```bash
  chattr +i baseline.json
  ```
  Even the `root` superuser cannot modify, delete, or rename this file until the immutable bit is explicitly removed via `chattr -i`.
- **WORM / Read-Only Storage**: Store the baseline database on a read-only NFS mount, optical WORM (Write Once, Read Many) media, or a cryptographically signed S3 bucket with Object Lock enabled.
- **HMAC / GPG Baseline Signing**: Baseline catalogs can be signed using a private GPG key stored in a hardware security module (HSM) or smart card, requiring public key verification prior to scan execution.

---

## 2. Log Integrity & Anti-Forensics Prevention

Adversaries frequently attempt **Indicator Removal (T1070)** by clearing `/var/log` or terminating logging processes.

### Countermeasures:
1. **Out-of-Band Remote Syslog Forwarding**:
   Audit logs (`logs/fim_events.jsonl`) should be shipped in near real-time via `rsyslog`, `syslog-ng`, or `FluentBit` over TLS to a remote, segregated SIEM cluster. Once emitted, the attacker cannot delete records from the remote collector.
2. **Append-Only File Attributes**:
   Protect local logs from truncation:
   ```bash
   chattr +a logs/fim_audit.log
   ```

---

## 3. Time-of-Check to Time-of-Use (TOCTOU) & Race Conditions

In user-space file integrity scanning, a small time window exists between:
1. Reading the file content and computing its SHA-256 hash.
2. Reading the file metadata (`stat` for permissions, owner, timestamps).

An advanced adversary could theoretically manipulate timestamps or swap files rapidly. To mitigate this:
- Files are opened in read-only binary mode (`"rb"`), locking file descriptors where supported by filesystem semantics.
- Scanning captures both cryptographic hashes and POSIX inode attributes; if an attacker replaces a file via atomic rename (`mv`), the inode number changes, which can be surfaced during forensic analysis.

---

## 4. Privilege Boundaries & Principle of Least Privilege

- **Unprivileged Execution**: When scanning public web trees (`/var/www/html`) or user binaries, the FIM utility can execute as a dedicated unprivileged user (`fim-runner`).
- **Privileged Targets**: Reading security-critical files like `/etc/shadow` (permissions `0640` or `0600`) requires root or `CAP_DAC_READ_SEARCH` capability.
- **Access Error Resilience**: When unprivileged users run the tool against protected files, the utility catches `PermissionError`, safely logs a structured security warning, and proceeds without crashing.

---

## 5. Defense-in-Depth Integration Matrix

| Layer | Technology | Complementary Role with FIM |
| :--- | :--- | :--- |
| **Integrity Detection** | **This FIM Utility** | Periodic cryptographic verification and forensic reporting. |
| **Kernel Event Audit** | **auditd / fanotify** | Real-time kernel syscall auditing capturing PID, UID, and process command lines. |
| **Mandatory Access Control** | **SELinux / AppArmor** | Confining daemons so web exploits cannot modify `/etc` or `/bin` regardless of root. |
| **Immutable File Attributes** | **chattr (+i / +a)** | Blocking write and truncate operations on critical configurations. |
| **SIEM & SOAR** | **Splunk / Wazuh / ELK** | Centralized correlation and automated isolation orchestration. |
