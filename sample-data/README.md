# Sample Data for File Integrity Testing

This directory provides a safe, mock Linux file hierarchy (`sample-data/etc`, `sample-data/bin`, `sample-data/var`) to test and demonstrate File Integrity Monitoring capabilities on any platform (Linux, Windows, macOS) without requiring root permissions or risking production system files.

## Directory Structure

```text
sample-data/
├── etc/
│   ├── passwd          # Mock user account database
│   ├── shadow          # Mock password hash storage
│   └── ssh/
│       └── sshd_config # Mock SSH server configuration
├── bin/
│   └── login           # Mock system login binary/script
└── var/
    └── log/
        └── auth.log    # Mock Linux authentication log
```

## Simulated Attack Scenarios for Portfolio Demos

You can simulate realistic attacker actions using the mock files:

1. **Backdoor Account Creation (Modification)**:
   Append an unauthorized user with UID 0 (root equivalent) to `sample-data/etc/passwd`:
   ```bash
   echo "backdoor:x:0:0:Backdoor User:/root:/bin/bash" >> sample-data/etc/passwd
   ```

2. **Trojan Binary Replacement (Modification)**:
   Modify the content of `sample-data/bin/login`:
   ```bash
   echo "#!/bin/bash\necho 'Compromised'" > sample-data/bin/login
   ```

3. **Malicious Persistence / Web Shell (New File)**:
   Drop an unauthorized backdoor file:
   ```bash
   echo "<?php system(\$_GET['cmd']); ?>" > sample-data/etc/cron.d/malicious_job
   ```

4. **Covering Tracks (Deletion)**:
   Delete an audit log file to simulate an intruder wiping evidence:
   ```bash
   rm sample-data/var/log/auth.log
   ```

Run `python main.py scan` after any of these changes to watch the FIM detect the tampering, flag the severity level, log the event, and generate a SOC incident report.
