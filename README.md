# SOC Home Lab — SOC Command v3.1

A beginner-friendly SOC (Security Operations Center) investigation lab built with Python Flask and SQLite. It runs locally on Kali Linux and provides sample security alerts to review, investigate, and document.

![SOC dashboard](screenshots/dashboard-overview.png)

## What the lab does

A SOC analyst checks security alerts, reviews the available evidence, and records what happened and what needs further investigation. This lab provides a small dashboard to practice that process.

The current project includes:

- **Dashboard overview:** a summary of the training environment.
- **Suricata alerts (`/alerts`):** three preloaded sample network alerts with timestamps, IP addresses, signatures, severity, and HTTP paths.
- **Alert investigations:** case status, disposition, and analyst notes saved to a local SQLite database.
- **Investigation queue (`/investigations`):** a place to review and filter investigation cases.
- **SSH and endpoint exercises (`/detections`):** separate training cases for host and authentication activity.
- **Incident capstone (`/capstone/CAPSTONE-001`):** a simulated investigation with a timeline and evidence.
- **Detection quality (`/quality`):** results from ten controlled synthetic test scenarios.

**Important:** The three Suricata alerts are synthetic training data included in the repository. The Flask dashboard does not capture live network traffic or automatically generate new alerts. It is an investigation lab, not a live SIEM.

## How the included alerts were created

### 1. Preparing the example events

Suricata is a network intrusion detection system (IDS). It normally writes detected events to an **EVE JSON** log, with one JSON object per line.

For this lab, three **synthetic examples** were prepared in the same JSON structure so they could be used for repeatable investigations without requiring live traffic.

The repository contains these completed records, but it does **not** document the original commands used to write each one. They should therefore be described as prepared sample events, not as alerts proven to have come from a packet capture or real attack.

### 2. The three alerts

| Sample alert | HTTP path | File |
| --- | --- | --- |
| Possible diagnostic script request | `/diag.sh` | `evidence/suricata-retest/eve.json` |
| HTTP unusual user agent | `/status` | `evidence/suricata-retest/eve.json` |
| Suspicious path probe | `/admin` | `evidence/attack-tests/suricata-fixed/eve.json` |

The first file contains two events; the second contains one. All three are already present when you clone the repository.

### 3. What an alert looks like

This is the `/admin` sample event from the project, formatted over several lines for readability:

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

- `timestamp`: the recorded event time.
- `event_type`: `alert` tells the application this is an alert event.
- `src_ip` and `dest_ip`: the source and destination IP addresses.
- `src_port` and `dest_port`: the connection ports.
- `alert.signature`: the name of the example detection.
- `alert.severity`: the assigned alert severity.
- `http.url`: the requested web path.

The IP addresses are reserved documentation addresses. The event is not proof that a real system was attacked.

### 4. How the dashboard reads the alerts

The `dashboard/app.py` file points to the two evidence files:

```python
SOURCES = [
    ROOT / "evidence/suricata-retest/eve.json",
    ROOT / "evidence/attack-tests/suricata-fixed/eve.json",
]
```

When the dashboard loads alerts:

1. `load_alerts()` opens both files and reads each JSON line.
2. It keeps events with `event_type` equal to `alert`.
3. It extracts the timestamp, signature, severity, source and destination, and HTTP path.
4. It assigns each alert an ID using its file path and line number.
5. `enrich_alerts()` adds saved case status, disposition, and notes from SQLite.
6. The browser displays the alerts on the `/alerts` page.

The JSON files provide the alert evidence; SQLite stores the analyst's investigation updates.

## How to set up and run the lab on Kali Linux

### Step 1 — Install the basic tools

Open a Kali terminal:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

### Step 2 — Download the project

```bash
cd ~
git clone https://github.com/irushimelettu-sudo/soc-home-lab.git
cd soc-home-lab
```

If you already downloaded it, use `cd ~/soc-home-lab` instead.

### Step 3 — Install the Python dependency

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The virtual environment keeps the project's Python packages separate from the rest of Kali. The requirements file installs Flask.

### Step 4 — Check the installation

```bash
python3 tests/smoke_test.py
```

The test checks that six dashboard pages respond successfully and that all **three synthetic Suricata alerts** load. It should finish with `[COMPLETE] Standalone smoke test passed`.

### Step 5 — Start the dashboard

```bash
python3 dashboard/app.py
```

Leave this terminal running and open the following address in Kali's browser:

**http://127.0.0.1:5000/**

Press **Ctrl+C** in the terminal to stop the dashboard.

## How to use the lab

1. Open the dashboard at `http://127.0.0.1:5000/`.
2. Go to **Alerts** (`/alerts`) to see the three sample Suricata events.
3. Open an alert and read its signature, timestamp, severity, source/destination, and HTTP path.
4. Open the alert's investigation and update its **status**, **disposition**, and **notes**. Statuses include New, Investigating, and Closed.
5. Save the case. The update is stored in the local SQLite database (`dashboard/cases.db`).
6. Visit **Investigations** (`/investigations`) to review tracked cases.
7. Explore **Detections**, **Capstone**, and **Quality** for the other included training exercises.

For example, the `/admin` alert represents a request to an administrative web path. That path can be suspicious, but the alert alone does not prove a compromise. The purpose of the investigation is to record the available evidence and what else would need to be checked.

## Testing and limitations

The included `tests/smoke_test.py` checks six routes and the three sample alerts. During separate validation on Kali, investigation-form updates, SQLite persistence, reading saved changes, and rejection of invalid status values were also checked using temporary database copies.

The detection-quality exercise contains **10 synthetic scenarios**: 3 true positives, 7 true negatives, 0 false positives, and 0 false negatives. These results are specific to the training exercise, not a measure of real-world accuracy.

This is a **local educational project**. It has no production authentication or CSRF protection and should not be exposed to the internet. The simulated capstone does not confirm compromise or script execution. New Suricata events are not automatically imported into the dashboard.

## Screenshots

### Dashboard

![Dashboard overview](screenshots/dashboard-overview.png)

### Investigations

![Investigation queue](screenshots/investigations.png)

### Detection quality

![Detection quality](screenshots/detection-quality.png)

### Capstone

![Capstone investigation](screenshots/capstone-investigation.png)

### Detection queue

![SOC detection queue](screenshots/soc-detection-queue.png)
