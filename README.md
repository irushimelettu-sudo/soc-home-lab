# SOC Home Lab — SOC Command v3.1

A Kali Linux / VirtualBox SOC analyst training project comprising twelve exercises and a simulated incident-response capstone. The dashboard uses Flask, SQLite, Suricata EVE alert records, SSH/endpoint detection staging, and controlled detector validation.

![SOC Command dashboard overview](screenshots/dashboard-overview.png)

## Key features

- Flask dashboard with SOC overview, investigation queue, detection quality, and case detail views.
- Suricata alert triage and SSH/endpoint detection staging with analyst status, disposition, and notes.
- Simulated incident-response capstone with a unified timeline and evidence-based conclusions.
- Controlled detector validation across 10 synthetic scenarios (3 TP, 7 TN, 0 FP, 0 FN); these are **not** production performance metrics.
- Standalone smoke test for six dashboard routes and three synthetic Suricata alerts.

## What is included

- `dashboard/`: SOC Command source and investigation workflow
- `evidence/`: **synthetic demo** Suricata EVE records and detection staging SQLite database
- `dashboard/cases.db`: **synthetic demo** Suricata case decisions
- `capstone/`: selected training investigation evidence and report
- `validation/`: controlled detector-quality results
- `tests/`: standalone demo smoke test

The demo cases are **not** copies of original lab databases. The capstone is a simulation: compromise and script execution were **not confirmed**. The 3 TP / 7 TN / 0 FP / 0 FN results describe ten controlled test scenarios only, not real-world accuracy.

## Safety and limitations

- **Local demonstration only.** The app binds to `127.0.0.1` by default and runs with debug mode disabled. Do not publish it to the internet or use it with untrusted users.
- The case-update forms do **not** currently implement CSRF protection or user authentication. Do not deploy the Flask development server as a public service.
- The repository includes intentionally tracked **synthetic demo SQLite databases**. Do not replace them with real case databases, credentials, raw customer logs, or private telemetry.
- The capstone is simulated; unauthorized access, script execution, persistence, and exfiltration were **not** established.
- Review all screenshots and evidence for sensitive information before sharing. The checks documented here are **not** a comprehensive security audit.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 tests/smoke_test.py
python3 dashboard/app.py
```

The smoke test is a separate check; it does not prove the entire dashboard is secure or production-ready.

Open http://127.0.0.1:5000/ . Use only on localhost; Flask's development server is not for production.

## Training topics

01 SSH investigation; 02 auditd/endpoint; 03 Suricata and PCAP; 04 Flask dashboard (developed inside Lab 03); 05 timeline; 06 detection staging; 07 endpoint investigation; 08 dashboard enhancement; 09 Suricata correlation; 10 PCAP threat hunting; 11 incident response; 12 detector-quality validation.

## Scope and provenance

The dashboard was tested in the original Kali environment, including case update persistence using temporary SQLite copies. This repository includes *separate synthetic demo data* to support reproducibility; original packet captures, raw logs, full databases, and backups are not published. Some capstone and validation evidence is selected from the training exercise and must receive final human review before public upload.

## Dashboard Screenshots

The SOC Command dashboard uses synthetic demonstration data.

### SOC Command Center

![SOC Command Center](screenshots/dashboard-overview.png)

### Investigation Queue

![Investigation Queue](screenshots/investigations.png)

### Detection Quality

![Detection Quality](screenshots/detection-quality.png)

### Capstone Investigation

![Capstone Investigation](screenshots/capstone-investigation.png)

### SOC Detection Queue

![SOC Detection Queue](screenshots/soc-detection-queue.png)
