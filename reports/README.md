# FIM Scan Reports Directory

This directory stores generated scan reports produced by the `--report` option or `python main.py report`.

## Report Formats

1. **Markdown (`.md`)**:
   - Executive Summary
   - Baseline vs. Current Scan Statistics
   - Detailed Anomaly Table (Modified, Added, Deleted, Metadata alterations)
   - Threat Context & MITRE ATT&CK Mapping
   - SOC Recommended Remediation Playbook

2. **JSON (`.json`)**:
   - Full programmatic scan artifact containing raw hash comparisons, timestamps, and metadata deltas.
   - Ideal for CI/CD pipelines, automated alerting webhooks, or SOC automation scripts.

3. **Text (`.txt`)**:
   - Concise plain-text summary suitable for automated email notifications or terminal displays.
