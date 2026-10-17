# SOC Home Lab — SOC Command v3.1

A local SOC investigation lab built on Kali Linux using Python, Flask, SQLite, and Suricata-format alert data. The project brings together network alert review, SSH and endpoint detection exercises, investigation tracking, and a simulated incident-response case.

![SOC dashboard](screenshots/dashboard-overview.png)

## Project overview

The dashboard is designed to practice the workflow of reviewing security events and recording investigation decisions. It includes:

- A dashboard overview and Suricata alert list
- Alert details such as timestamp, signature, severity, source and destination addresses, and HTTP path
- Case status, disposition, and analyst notes saved in SQLite
- An investigation queue and separate SSH/endpoint detection examples
- A simulated incident timeline and detection-quality results

The published dashboard uses **three synthetic Suricata-format alerts**. They are stored in the repository so the application works without a running network sensor. This is a training environment, not a live SIEM.

## Requirements

- Kali Linux (or another Linux system with Python 3)
- Git
- Python 3.10 or newer and Python virtual environment support
- A web browser

## Installation and running the dashboard

**1. Install the required tools on Kali:**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

**2. Clone the repository:**

```bash
cd ~
git clone https://github.com/irushimelettu-sudo/soc-home-lab.git
cd soc-home-lab
```

If the repository is already cloned, run `cd ~/soc-home-lab` instead.

**3. Set up Python:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**4. Check that the application works:**

```bash
python3 tests/smoke_test.py
```

The test checks six dashboard routes and confirms that the three bundled Suricata alerts can be loaded.

**5. Start the dashboard:**

```bash
python3 dashboard/app.py
```

Open **http://127.0.0.1:5000/** in the Kali browser. Keep the terminal running while using the application. Press **Ctrl+C** to stop the server.

## How the alert data was created and used

Suricata is a network intrusion detection system. When traffic matches a detection rule, Suricata can record an event in its EVE JSON log. An EVE JSON file contains one JSON event per line.

For the public version of this lab, the three dashboard alerts are **synthetic example records** written in Suricata's EVE JSON structure. This keeps the exercise reproducible and avoids including original raw traffic or private logs. The repository contains the finished records; it does not contain a complete record of the original commands used to author each synthetic example.

### 1. The alert records

Two events are stored in:

```text
evidence/suricata-retest/eve.json
```

They represent:

- `LAB DEMO Possible diagnostic script request` — HTTP request for `/diag.sh`
- `LAB DEMO HTTP unusual user agent` — HTTP request for `/status`

One event is stored in:

```text
evidence/attack-tests/suricata-fixed/eve.json
```

It represents:

- `LAB DEMO Suspicious path probe` — HTTP request for `/admin`

These are sample detection scenarios, not confirmed intrusions.

### 2. Structure of an alert

This is one of the synthetic events included in the project, formatted for readability:

```json
{
  "timestamp": "2026-10-17T20:12:00+05:30",
  "event_type": "alert",
  "src_ip": "192.0.2.10",
  "src_port": 49152,
  "dest_ip": "198.51.100.20",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "signature": "LAB DEMO Suspicious path probe",
    "signature_id": 1000003,
    "severity": 2
  },
  "http": {
    "url": "/admin",
    "hostname": "demo.example"
  }
}
```

The `timestamp` records the event time, `src_ip` and `dest_ip` identify the endpoints, `signature` names the detection, `severity` gives its assigned priority, and `http.url` records the requested path. The IP addresses used in the samples are documentation addresses.

### 3. Loading the records into Flask

In `dashboard/app.py`, the application points to the two evidence files:

```python
SOURCES = [
    ROOT / "evidence/suricata-retest/eve.json",
    ROOT / "evidence/attack-tests/suricata-fixed/eve.json",
]
```

The `load_alerts()` function reads each JSON line and selects events with `event_type` set to `alert`. It extracts the relevant fields, assigns an ID based on the source file and line number, and sorts the alerts by timestamp.

The `enrich_alerts()` function then adds any saved case status, disposition, and notes from the local SQLite database.

### 4. Reviewing an alert

After starting the dashboard, open **http://127.0.0.1:5000/alerts** and select an alert.

The investigation page allows the event details to be reviewed and a case to be updated. The available statuses are **New**, **Investigating**, and **Closed**. Dispositions include **Needs Investigation**, **True Positive**, **False Positive**, and **Benign True Positive**.

Changes and analyst notes are stored locally in `dashboard/cases.db`. An alert alone does not establish that an attack succeeded; it needs supporting evidence.

## Other lab components

### SSH and endpoint detections

The `/detections` page contains separate detection exercises for reviewing host and authentication-related activity and documenting case decisions.

### Investigation queue

The `/investigations` page brings together tracked investigation cases and provides filtering by status and severity.

### Incident-response capstone

The `/capstone/CAPSTONE-001` page presents a simulated SSH-related investigation timeline, including login activity and subsequent commands. The available evidence does **not** confirm compromise or script execution.

### Detection quality

The `/quality` page presents results from ten controlled synthetic scenarios: three true positives, seven true negatives, zero false positives, and zero false negatives. These figures describe that exercise only, not production detection accuracy.

## Screenshots

### Dashboard overview

![Dashboard overview](screenshots/dashboard-overview.png)

### Investigation queue

![Investigation queue](screenshots/investigations.png)

### Detection quality

![Detection quality](screenshots/detection-quality.png)

### Capstone investigation

![Capstone investigation](screenshots/capstone-investigation.png)

### SOC detection queue

![SOC detection queue](screenshots/soc-detection-queue.png)

## Testing and validation

### Dashboard smoke test

Run this command from the project directory:

```bash
python3 tests/smoke_test.py
```

The test uses Flask's test client to check that these six routes return HTTP **200** (successful response): `/`, `/investigations`, `/quality`, `/alerts`, `/detections`, and `/capstone/CAPSTONE-001`. It also checks that the dashboard loads exactly **three synthetic Suricata alerts**.

The smoke test checks basic functionality only. It does not test every user action or assess application security.

### Investigation form and database checks

During validation in the original Kali environment, the Suricata and Detection Staging investigation forms were tested by submitting updates (**POST**), checking that changes were saved in SQLite, and loading the case again (**GET**) to confirm that the saved values could be read back. Invalid case-status values were also checked for rejection.

Those database checks used **isolated temporary SQLite copies** to avoid changing the demonstration databases. They are documented validation results, **not** additional checks performed by the current `tests/smoke_test.py` script.

### Controlled detection results

The detector-quality exercise covered ten synthetic scenarios:

| Result | Count |
| --- | ---: |
| True positives | 3 |
| True negatives | 7 |
| False positives | 0 |
| False negatives | 0 |

These results apply only to the controlled scenarios and must not be interpreted as production detection accuracy.

## Notes and limitations

- The dashboard is intended for local use at `127.0.0.1`; do not expose the Flask development server publicly.
- The app does not implement production authentication or CSRF protection.
- The published evidence and SQLite demonstration databases are synthetic and intentionally included so the lab can be reproduced. Do not commit private logs, credentials, or real incident data.
- Investigation updates are saved to local SQLite files. To reset them, restore the demo databases from Git **only if you do not need to keep your local changes**.
- New Suricata events are not automatically ingested by the default dashboard.
- The Flask development server is not suitable for production, and the documented checks are not a full security or end-to-end assessment.

