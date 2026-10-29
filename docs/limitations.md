# Limitations & Comparative Analysis

Engineering transparent security software requires recognizing architectural boundaries and operational trade-offs. This document outlines the technical limitations of periodic user-space File Integrity Monitoring compared to enterprise and kernel-level solutions.

---

## 1. Architectural Boundaries

### 1.1 Periodic Polling vs. Real-Time Event Hooking
- **Periodic Scanning (This Utility)**: Operates on a scheduled interval (e.g., hourly via cron or systemd timer). A transient attacker who drops a file, executes it in RAM, and deletes it within the scan window may evade detection.
- **Real-Time Kernel Event Monitoring (`fanotify` / `inotify` / `auditd`)**: Monitors Linux VFS (Virtual File System) syscalls in real-time (`open`, `modify`, `close_write`, `unlink`). Enterprise tools like Wazuh combine periodic hashing with real-time inotify hooks.

### 1.2 Kernel Rootkits (LKM) & Syscall Interception
- **The Userland Dilemma**: Any utility running in user space (Ring 3) relies on kernel system calls (`sys_read`, `sys_openat`, `sys_getdents64`).
- If an adversary deploys a Loadable Kernel Module (LKM) rootkit (e.g., `Diamorphine`, `Reptile`), the rootkit can hook `sys_getdents64` to hide backdoor files from directory listings, or hook `sys_read` to return the original clean file bytes when a hashing process reads `/bin/login`.
- **Mitigation**: Kernel lockdown mode (`lockdown=integrity`), signed kernel modules (`module.sig_enforce=1`), and secure boot (UEFI).

---

## 2. Scalability & Resource Footprint

| Metric | Scoped System Monitoring (`/etc`, `/bin`, `/sbin`) | Full Disk Monitoring (`/`, millions of files) |
| :--- | :--- | :--- |
| **Typical Target Size** | ~1,000 to 10,000 files | 500,000+ files |
| **I/O Overhead** | Negligible (< 100 MB read) | High disk I/O saturation |
| **Execution Duration** | < 1 to 5 seconds | 10 to 45+ minutes |
| **Recommended Scope** | **Ideal for this utility** | Best handled by block-level or agent streaming |

**Engineering Recommendation**: FIM should target high-value, static system configurations (`/etc`, `/bin`, `/usr/bin`, `/boot`, web application roots) rather than rapidly mutating data trees (`/var/tmp`, `/dev`, `/proc`, `/sys`).

---

## 3. Comparative Matrix: FIM Architectures

| Capability | This FIM Utility | Linux auditd | Wazuh / OSSEC | Tripwire Enterprise |
| :--- | :--- | :--- | :--- | :--- |
| **Language & Engine** | Python 3 (Standard Lib) | C (Kernel subsystem) | C / Python | C++ |
| **Detection Method** | SHA-256 Hashing + POSIX Stat | Syscall Auditing | Hashing + inotify | Hashing + DB signing |
| **External Dependencies** | **Zero (Pure StdLib)** | auditd daemon | Agents + Managers | Agent + Server |
| **Real-time Hooking** | Scheduled Polling | Real-time (Kernel) | Real-time & Scheduled | Scheduled |
| **SIEM Ready JSONL** | **Native out-of-the-box** | Raw syslog / ausearch | Native JSON socket | Proprietary API |
| **Deployment Complexity** | **Zero Setup (Standalone)** | Medium | High | High |
| **Cross-Platform Testability** | **Native (Linux/Win/Mac)** | Linux only | Multi-platform | Multi-platform |

---

## 4. Future Roadmap & Enhancement Horizons

1. **Kernel Event Integration**: Incorporate optional `pyinotify` or `selectors` daemon mode for real-time file event triggers.
2. **Asymmetric GPG Baseline Signing**: Embed RSA/Ed25519 digital signatures into `baseline.json` verified via public keys.
3. **Automated Webhook Dispatch**: Direct alert dispatch to Slack, Microsoft Teams, or Jira for SOC ticketing.
