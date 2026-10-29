# Installation & Operational Usage Guide

This guide details deployment, configuration, routine operational workflows, and automated scheduling for the **Linux File Integrity Monitoring (FIM)** utility.

---

## 1. Prerequisites & Installation

### Requirements
- **Python**: Version 3.8 or higher (`python3 --version`)
- **OS Compatibility**: Native Linux (Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky, Alpine), macOS, and Windows
- **Dependencies**: Built purely with Python Standard Library (`hashlib`, `pathlib`, `json`, `logging`, `argparse`). Zero external packages required.

### Quick Clone & Verification
```bash
# Clone the repository
git clone https://github.com/yogeshscore442/linux-file-integrity-monitor.git
cd linux-file-integrity-monitor

# Run automated test suite to verify cryptographic engine
python3 -m unittest discover tests
```

---

## 2. Command Reference

### `1. init` - Establish Initial Baseline
Establishes an authorized cryptographic inventory of target files using SHA-256.

```bash
# Initialize using default targets from config/monitor_config.json
python3 main.py init

# Initialize with explicit custom directory targets
python3 main.py init --targets /etc /bin /usr/bin

# Overwrite existing baseline without interactive confirmation prompt
python3 main.py init --force
```

### `2. scan` - Verify Integrity Against Baseline
Performs a recursive differential scan, logs events to text and JSONL audit files, and generates incident reports.

```bash
# Standard scan with Markdown incident report generation
python3 main.py scan

# Generate all report formats (Markdown + JSON)
python3 main.py scan --format all

# Run silently in scripts without generating report files (returns exit codes)
python3 main.py scan --no-report
```

#### Exit Codes for Scripting & CI/CD:
- `0`: **Clean** — All monitored files match the baseline.
- `1`: **Operational Error** — Missing baseline, unreadable config, or I/O failure.
- `2`: **Integrity Violation** — Modifications, deletions, additions, or permission changes detected!

### `3. status` - Inspect FIM State & Environment
Displays baseline creation timestamps, file counts, catalog SHA-256 checksums, and audit log file paths.

```bash
python3 main.py status
```

### `4. update` - Explicit Baseline Refresh
Refreshes the baseline database after authorized system updates (e.g., `apt upgrade`, configuration rollouts). **Never runs automatically.**

```bash
# Interactive confirmation prompt
python3 main.py update

# Non-interactive update for Ansible/Puppet deployment scripts
python3 main.py update --force
```

### `5. verify` - Single-File Quick Check
Directly validates a specific file against the baseline database.

```bash
python3 main.py verify /etc/passwd
```

### `6. demo` - Automated Attack Simulation
Executes an end-to-end self-contained simulation of adversary tampering (T1098 backdoor user injection, T1036 trojan drop, T1070 log wiping), triggers detection, produces incident reports, and restores the environment.

```bash
python3 main.py demo
```

---

## 3. Production Linux Hardening Configuration

To monitor live Linux operating system directories, edit `config/monitor_config.json`:

```json
{
  "settings": {
    "hash_algorithm": "sha256",
    "chunk_size_bytes": 65536,
    "follow_symlinks": false,
    "baseline_file": "/var/lib/fim/baseline.json",
    "log_file": "/var/log/fim/fim_audit.log",
    "events_jsonl": "/var/log/fim/fim_events.jsonl",
    "reports_dir": "/var/log/fim/reports"
  },
  "monitoring": {
    "monitored_paths": [
      "/etc",
      "/bin",
      "/sbin",
      "/usr/bin",
      "/usr/sbin",
      "/boot",
      "/var/spool/cron"
    ],
    "exclude_patterns": [
      "*.tmp",
      "*.swp",
      "/etc/mtab",
      "/etc/resolv.conf"
    ]
  }
}
```

---

## 4. Automation & Scheduled Monitoring

### Option A: Crontab Job (Hourly / Daily)
Schedule the integrity verification to run automatically every hour:

```bash
# Open root crontab
sudo crontab -e

# Run scan every hour; alert on exit code 2
0 * * * * cd /opt/linux-file-integrity-monitor && python3 main.py scan --format all > /dev/null 2>&1
```

### Option B: Systemd Service & Timer

1. Create `/etc/systemd/system/fim-scan.service`:
```ini
[Unit]
Description=Linux File Integrity Verification Scan
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/opt/linux-file-integrity-monitor
ExecStart=/usr/bin/python3 main.py scan --format all
User=root
StandardOutput=journal
StandardError=journal
```

2. Create `/etc/systemd/system/fim-scan.timer`:
```ini
[Unit]
Description=Run FIM scan every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
```

3. Enable and activate the timer:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fim-scan.timer
```

---

## 5. SIEM Integration (Wazuh, Splunk, Elastic)

The JSON Lines event stream (`logs/fim_events.jsonl`) produces standardized records ready for ingestion:

### Filebeat Configuration (`filebeat.yml`):
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/linux-file-integrity-monitor/logs/fim_events.jsonl
    json.keys_under_root: true
    json.add_error_key: true
```

### Wazuh Agent (`ossec.conf`):
```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/linux-file-integrity-monitor/logs/fim_events.jsonl</location>
</localfile>
```
