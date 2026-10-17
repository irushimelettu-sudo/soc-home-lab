# SOC Home Lab — SOC Command v3.1

A beginner-friendly **SOC analyst investigation lab** built with Python Flask, SQLite, and **synthetic Suricata-format alerts**. It also includes SSH/endpoint detection exercises, a simulated incident-response capstone, and controlled detector validation.

![SOC dashboard](screenshots/dashboard-overview.png)

> **What this project really does:** It loads three example alerts from JSON files and lets you investigate and document them in a browser. It does **not** capture network packets, run Suricata, or automatically create/import new alerts. You can run the published dashboard without installing Suricata.

## 1. What is a SOC and what am I learning?

A **Security Operations Center (SOC)** analyst reviews security alerts, checks evidence, decides whether more investigation is needed, and documents findings.

- **Suricata:** a network intrusion detection system (IDS). It can detect traffic matching rules and record events in EVE JSON format.
- **EVE JSON:** a log format in which each line contains one JSON event. This project uses **synthetic records shaped like Suricata events**.
- **Flask:** the Python framework that displays the dashboard in a browser.
- **SQLite:** a small local database used to save analyst case decisions and notes.
- **Triage:** the first review of an alert to decide what to investigate next.
- **Signature:** the name of the detection rule that matched, or—in this project's synthetic data—the rule being represented.
- **False positive:** an alert incorrectly indicating the activity of interest; do not label something a false positive without evidence.

## 2. What is actually included?

| Component | Purpose |
| --- | --- |
| `dashboard/app.py` | Flask dashboard; loads example alerts and provides investigation pages |
| `evidence/suricata-retest/eve.json` | Two synthetic Suricata-format alert events |
| `evidence/attack-tests/suricata-fixed/eve.json` | One more synthetic Suricata-format alert event |
| `dashboard/cases.db` | Local SQLite case tracking for Suricata alert investigations |
| `/detections` page | Separate SSH/endpoint detection training queue |
| `/investigations` page | Review investigation progress |
| `/capstone/CAPSTONE-001` page | Simulated incident timeline and analysis |
| `/quality` page | Controlled detector validation results |
| `tests/smoke_test.py` | Checks six pages and confirms three bundled alerts |

The public demo data is synthetic. The capstone does **not** establish that compromise or script execution occurred. The controlled detector results (3 true positives, 7 true negatives, 0 false positives, 0 false negatives) cover **10 synthetic test scenarios**, not real-world detection accuracy.

## 3. Start the lab from zero (Kali Linux)

Run the following commands **inside the Kali terminal**, not on GitHub.

### Step 1 — Install Git and Python tools

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

Already cloned it? Just run `cd ~/soc-home-lab` instead.

### Step 3 — Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

A virtual environment keeps the project's Python packages separate from the rest of Kali. You should see `(.venv)` in your terminal prompt.

### Step 4 — Install Flask

```bash
pip install -r requirements.txt
```

The repository's requirements file specifies Flask 3.x.

### Step 5 — Test the dashboard before launching it

```bash
python3 tests/smoke_test.py
```

Expected output includes six `[PASS]` HTTP 200 checks, `[PASS] 3 synthetic Suricata alerts`, and `[COMPLETE] Standalone smoke test passed`. This is a basic functionality test, not a security audit.

### Step 6 — Start the dashboard

```bash
python3 dashboard/app.py
```

**Keep this terminal open.** Open Kali's browser and visit:

**http://127.0.0.1:5000/**

The server runs locally on your machine. To stop it, return to the terminal and press **Ctrl+C**. Run `deactivate` when finished using the Python environment.

### Step 7 — Where to click

1. **Overview** — explain the lab's purpose and dashboard summaries.
2. **Suricata Alerts** — visit **http://127.0.0.1:5000/alerts** and open one of the three sample alerts.
3. **Alert investigation** — review the alert's fields; change the case status and write notes.
4. **Investigations** — visit `/investigations` to review tracked cases.
5. **SOC Detections** — visit `/detections` for the separate SSH/endpoint training examples.
6. **Capstone** — visit `/capstone/CAPSTONE-001` for a simulated investigation.
7. **Detection Quality** — visit `/quality` and explain the limits of the ten controlled scenarios.

## 4. How were the three dashboard alerts created?

**Verified from the published repository:** the three alerts are **synthetic EVE JSON examples stored as text**, not live network events. The repository does not document the original authoring commands for each sample record. The steps below explain **how the published example records are represented and displayed**; they do not claim an undocumented packet capture or attack occurred.

### Step 1 — Prepare Suricata-shaped JSON events

Each event is a single JSON object on one line, with fields such as:

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

This is a formatted illustration of **one actual synthetic record** in the repository. The IP addresses belong to documentation/test ranges; they are not evidence of a real external attacker.

### Step 2 — Store the three events in the evidence folder

The published project contains:

| Evidence file | Synthetic signature | HTTP path |
| --- | --- | --- |
| `evidence/suricata-retest/eve.json` | `LAB DEMO Possible diagnostic script request` | `/diag.sh` |
| `evidence/suricata-retest/eve.json` | `LAB DEMO HTTP unusual user agent` | `/status` |
| `evidence/attack-tests/suricata-fixed/eve.json` | `LAB DEMO Suspicious path probe` | `/admin` |

These records are **already included** when you clone the repository. No network attack, traffic replay, or rule execution is necessary to make them appear.

### Step 3 — Flask reads those two files

In `dashboard/app.py`, the actual configuration is:

```python
SOURCES = [
    ROOT / "evidence/suricata-retest/eve.json",
    ROOT / "evidence/attack-tests/suricata-fixed/eve.json",
]
```

The `load_alerts()` function reads each line as JSON, keeps records where `event_type == "alert"`, extracts the signature, severity, timestamp, source/destination and HTTP URI, and sorts the results by timestamp. The alert's evidence path and line number form its case ID.

### Step 4 — The dashboard displays the records

The `/alerts` page shows the loaded alerts. `enrich_alerts()` combines them with any saved analyst status, disposition and notes from SQLite.

### Step 5 — The analyst reviews and documents the evidence

You can open an alert, set its status (such as **Investigating**), choose a disposition (such as **Needs Investigation**), write an evidence-based note, and save the case.

**Important distinction:** This is an **alert investigation and case-management workflow**, not an automatic detection pipeline. A signature label is not proof that malicious activity occurred.

## 5. Beginner practice: investigate one alert

1. Start the dashboard and open **/alerts**.
2. Select the synthetic **Suspicious path probe** alert (the `/admin` request).
3. Explain each field:
   - **Timestamp:** when the synthetic event says it occurred.
   - **Source IP/port:** the client side of the recorded connection.
   - **Destination IP/port:** the server side of the recorded connection.
   - **Signature:** the rule or behavior represented by the example.
   - **Severity:** the alert's assigned priority, not proof of impact.
   - **URI `/admin`:** the requested web path; it can be legitimate or suspicious depending on context.
4. Open the investigation case. Set **Status: Investigating** and **Disposition: Needs Investigation**.
5. Write a note such as:

   > Reviewed synthetic HTTP path-probe alert for /admin. The rule label and requested path warrant context review, but this record alone does not prove compromise. Next steps: compare with web-server logs, authentication activity and related requests.

6. Save the case and reopen it to show that SQLite retains the note.
7. Open **/investigations** and explain how analysts track cases.

**What the analyst should say:** "I observed an alert, checked its available evidence, documented what is known and unknown, and identified the next evidence to collect. I did not assume an attack succeeded just because an alert appeared."

## 6. Optional background: how a real Suricata alert is generated

This is **not part of the default published dashboard** and is **not needed to run the lab**. It explains a separate experiment performed on Kali. The original dashboard **does not read** the log created below.

Suricata itself can generate alerts when network traffic matches a detection rule. In the separate localhost experiment, the following steps were successfully used:

### A — Install/check Suricata

```bash
sudo apt install -y suricata curl
suricata -V
```

### B — Write a simple test rule

```bash
mkdir -p ~/soc-live-demo
cat > ~/soc-live-demo/demo.rules <<'EOF'
alert http any any -> any any (msg:"SOC LAB - Live HTTP Demo Alert"; flow:established,to_server; http.uri; content:"/soc-lab-test"; sid:1000001; rev:1;)
EOF
```

The rule says: alert when an established HTTP request contains `/soc-lab-test` in the URI. It is a **training rule**, not a general-purpose malicious-traffic detector.

### C — Validate the rule

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -S ~/soc-live-demo/demo.rules
```

### D — Use three Kali terminals

**Terminal 1 — Monitor local traffic:**

```bash
sudo mkdir -p /var/log/suricata/soc-live-demo
sudo suricata -c /etc/suricata/suricata.yaml -S ~/soc-live-demo/demo.rules -i lo -l /var/log/suricata/soc-live-demo
```

**Terminal 2 — Start a local web server:**

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

**Terminal 3 — Send a harmless request:**

```bash
curl -v http://127.0.0.1:8088/soc-lab-test
```

A **404 response is expected and acceptable**: Suricata checks the request path, not whether the page exists.

### E — Verify the newly generated event

```bash
sudo grep 'SOC LAB - Live HTTP Demo Alert' /var/log/suricata/soc-live-demo/eve.json
```

The earlier Kali experiment produced an alert event with signature ID `1000001`, HTTP URI `/soc-lab-test`, localhost IPs and destination port `8088`.

**What happened:** HTTP request → Suricata inspected traffic on `lo` → custom rule matched → Suricata wrote an alert to its EVE JSON log.

Press **Ctrl+C** in Terminals 1 and 2 to stop the processes. The rule and generated log are stored **outside** `~/soc-home-lab`; they are not part of the published Flask application's alert sources.

**Interview distinction:** "I separately proved I could write and trigger a Suricata detection rule on my own Kali machine. The published Flask dashboard still uses three bundled synthetic records, not this live log."

## 7. Interview demo: what to show and what to say (5–10 minutes)

| Time | Show | Explain |
| --- | --- | --- |
| Minute 1 | Dashboard overview | "This is a local SOC analyst training project using Flask and SQLite." |
| Minute 2 | `/alerts` | "These three examples are synthetic Suricata-format JSON records, so the lab is reproducible." |
| Minutes 3–4 | Open an alert | "I review the signature, severity, source/destination, timestamp and URI before deciding what to do." |
| Minute 5 | Save status and note | "My investigation decisions persist in SQLite. A detection alone does not prove compromise." |
| Minute 6 | `/investigations` and `/detections` | "I can track alert cases and work through separate SSH/endpoint exercises." |
| Minutes 7–8 | Capstone | "This is a simulated SSH-related timeline. Compromise and script execution were not confirmed." |
| Minute 9 | `/quality` | "The results come from ten controlled scenarios; they do not predict production accuracy." |
| Minute 10 | Architecture and limitations | "The dashboard reads fixed JSON files. I tested a separate Suricata rule on Kali, but the dashboard is not a live SIEM." |

### Common interviewer questions

**Q: How did you create the alerts shown in the dashboard?**

A: "The published demo uses three synthetic Suricata-format JSON events in two evidence files. Flask parses those records and displays them for triage. The exact original creation commands for each sample event are not documented, so I describe them as synthetic training data."

**Q: Did you use real Suricata?**

A: "Yes, in a separate localhost experiment. I wrote an HTTP URI rule, validated it, sent a request with curl and confirmed a new alert in Suricata's EVE JSON output. That event is not automatically imported into this dashboard."

**Q: Does the dashboard detect attacks automatically?**

A: "No. The published dashboard is for investigation and case management using predefined evidence. It does not run Suricata or monitor live traffic."

**Q: What would you do after seeing a suspicious alert?**

A: "Check the available event details, correlate with related network, web and host logs, assess possible benign explanations, document the evidence, and escalate when justified."

**Q: Why use SQLite?**

A: "It gives a simple way to persist case status, disposition and analyst notes without needing a separate database server."

**Q: What would you improve next?**

A: "A properly tested ingestion pipeline for new EVE JSON events, safer case IDs, authentication, CSRF protection, and stronger automated tests. Those are future improvements, not features I claim are already implemented."

## 8. Troubleshooting

**`git clone` says the directory exists:** use `cd ~/soc-home-lab` instead.

**`pip` or Flask is missing:** activate the virtual environment and rerun `pip install -r requirements.txt`.

**Browser cannot connect:** check that `python3 dashboard/app.py` is still running and that you opened `http://127.0.0.1:5000/` on Kali.

**Only three alerts appear:** that is expected. They are the three bundled examples.

**The optional Suricata event does not appear on `/alerts`:** also expected. The default Flask app does not read `/var/log/suricata/soc-live-demo/eve.json`.

**The smoke test fails after editing files:** return to the repository's documented default setup; the test expects exactly three bundled Suricata alerts.

## 9. Safety and scope

- This is a **localhost educational demo**, not a production SIEM.
- The Flask app does not include production authentication or CSRF protection. Do not expose it to the internet or untrusted users.
- Do not upload real incident logs, private packet captures, credentials, personal data or customer databases.
- The included SQLite databases are synthetic demonstration data. Analyst edits to the local database may persist between sessions.
- The capstone is simulated. Do not claim compromise, persistence, script execution or exfiltration were proven.
- The detector-quality results describe only ten controlled synthetic scenarios.

## 10. Screenshots

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

## Additional notes

See [SETUP.md](SETUP.md) for concise setup and safety notes and [VALIDATION.md](VALIDATION.md) for the documented validation scope.
