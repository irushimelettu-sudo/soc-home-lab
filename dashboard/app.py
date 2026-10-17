# SOC_HOMEPAGE_V1
#!/usr/bin/env python3

import json
import sqlite3
from pathlib import Path
from collections import Counter
from flask import Flask, request, redirect, url_for, render_template_string, abort

app = Flask(__name__)

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "dashboard/cases.db"

SOURCES = [
    ROOT / "evidence/suricata-retest/eve.json",
    ROOT / "evidence/attack-tests/suricata-fixed/eve.json",
]

STATUSES = ("New", "Investigating", "Closed")
DISPOSITIONS = (
    "Needs Investigation",
    "True Positive",
    "False Positive",
    "Benign True Positive",
)

def connect():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                alert_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'New',
                disposition TEXT NOT NULL DEFAULT 'Needs Investigation',
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

def load_alerts():
    alerts = []

    for source in SOURCES:
        if not source.exists():
            continue

        with source.open() as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert = event.get("alert", {})
                http = event.get("http", {})

                relative_source = str(source.relative_to(ROOT))
                alert_id = f"{relative_source}:{line_number}"

                alerts.append({
                    "id": alert_id,
                    "timestamp": event.get("timestamp", ""),
                    "signature": alert.get("signature", ""),
                    "sid": alert.get("signature_id", ""),
                    "severity": alert.get("severity", ""),
                    "source": f"{event.get('src_ip', '')}:{event.get('src_port', '')}",
                    "destination": f"{event.get('dest_ip', '')}:{event.get('dest_port', '')}",
                    "uri": http.get("url", ""),
                    "evidence": relative_source,
                })

    return sorted(alerts, key=lambda a: a["timestamp"], reverse=True)

def enrich_alerts():
    alerts = load_alerts()

    with connect() as db:
        cases = {
            row["alert_id"]: dict(row)
            for row in db.execute("SELECT * FROM cases")
        }

    for alert in alerts:
        case = cases.get(alert["id"], {})
        alert["status"] = case.get("status", "New")
        alert["disposition"] = case.get("disposition", "Needs Investigation")
        alert["notes"] = case.get("notes", "")

    return alerts

BASE_STYLE = """
<style>
body {
    background:#0b1220; color:#e5e7eb;
    font-family:Arial,sans-serif; margin:0; padding:28px;
}
h1 {color:#38bdf8}
a {color:#7dd3fc}
.subtitle {color:#94a3b8}
.cards {
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
    gap:15px; margin:24px 0;
}
.card {
    background:#172235; border:1px solid #334155;
    border-radius:10px; padding:20px;
}
.number {font-size:30px;font-weight:bold;color:#38bdf8}
.label {color:#94a3b8;margin-top:8px}
table {width:100%;border-collapse:collapse;background:#172235}
th,td {
    padding:13px;text-align:left;
    border-bottom:1px solid #334155;vertical-align:top;
}
th {color:#38bdf8}
.table-wrap {overflow-x:auto}
input,select,textarea {
    background:#172235;color:#fff;
    border:1px solid #475569;
    border-radius:7px;padding:11px;
    box-sizing:border-box;
}
textarea {width:100%;min-height:160px}
button {
    background:#0284c7;color:white;
    border:0;border-radius:7px;
    padding:11px 18px;cursor:pointer;
}
small {color:#94a3b8}
.field {margin:18px 0}
.field label {display:block;margin-bottom:8px}
</style>
"""

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Investigation Console</title>
""" + BASE_STYLE + """
</head>
<body>

<!-- SOC_GLOBAL_NAV_V1 -->
<nav style="
  display:flex;
  gap:20px;
  flex-wrap:wrap;
  padding:14px 18px;
  margin-bottom:24px;
  background:#162236;
  border:1px solid #334155;
  border-radius:10px;
  font-family:Arial,sans-serif;
">
  <a href="/" style="color:#7dd3fc;">Overview</a>
  <a href="/investigations" style="color:#7dd3fc;">Investigations</a>
  <a href="/" style="color:#7dd3fc;">Suricata Alerts</a>
  <a href="/detections" style="color:#7dd3fc;">SOC Detections</a>
</nav>



<!-- SOC LAB 06 NAVIGATION -->
<div style="margin:16px 0;padding:12px 16px;
            background:#17364b;border-radius:8px;">
  <a href="/detections"
     style="color:#8bd6ff;font-weight:bold;
            text-decoration:none;">
    SSH Detections &rarr;
  </a>
</div>
<h1>SOC Investigation Console</h1>
<p class="subtitle">Suricata alert triage | Persistent analyst case tracking</p>

<div class="cards">
<div class="card">
<div class="number">{{ alerts|length }}</div>
<div class="label">Total Alerts</div>
</div>
<div class="card">
<div class="number">{{ counts["New"] }}</div>
<div class="label">New</div>
</div>
<div class="card">
<div class="number">{{ counts["Investigating"] }}</div>
<div class="label">Investigating</div>
</div>
<div class="card">
<div class="number">{{ counts["Closed"] }}</div>
<div class="label">Closed</div>
</div>
</div>

<form method="get">
<input name="q" value="{{ query }}"
       placeholder="Search alert, IP, URI, disposition...">
<button type="submit">Search</button>
</form>

<h2>Alert Queue</h2>

<div class="table-wrap">
<table>
<thead>
<tr>
<th>Time</th>
<th>Detection</th>
<th>Source</th>
<th>HTTP URI</th>
<th>Status</th>
<th>Disposition</th>
<th>Action</th>
</tr>
</thead>
<tbody>
{% for a in filtered %}
<tr>
<td>{{ a.timestamp }}</td>
<td>
<strong>{{ a.signature }}</strong><br>
<small>SID {{ a.sid }}</small>
</td>
<td>{{ a.source }}</td>
<td>{{ a.uri }}</td>
<td>{{ a.status }}</td>
<td>{{ a.disposition }}</td>
<td>
<a href="{{ url_for('case_detail', alert_id=a.id) }}">
Investigate
</a>
</td>
</tr>
{% else %}
<tr><td colspan="7">No matching alerts.</td></tr>
{% endfor %}
</tbody>
</table>
</div>

<p class="subtitle">
Case decisions are stored locally in SQLite.
Detection does not establish successful exploitation.
</p>

</body>
</html>
"""

CASE_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alert Investigation</title>
""" + BASE_STYLE + """
</head>
<body>

<!-- SOC_GLOBAL_NAV_V1 -->
<nav style="
  display:flex;
  gap:20px;
  flex-wrap:wrap;
  padding:14px 18px;
  margin-bottom:24px;
  background:#162236;
  border:1px solid #334155;
  border-radius:10px;
  font-family:Arial,sans-serif;
">
  <a href="/" style="color:#7dd3fc;">Overview</a>
  <a href="/investigations" style="color:#7dd3fc;">Investigations</a>
  <a href="/" style="color:#7dd3fc;">Suricata Alerts</a>
  <a href="/detections" style="color:#7dd3fc;">SOC Detections</a>
</nav>


<p><a href="{{ url_for('dashboard') }}">← Back to Alert Queue</a></p>

<h1>Alert Investigation</h1>

<div class="card">
<h2>{{ a.signature }}</h2>
<p><strong>Signature ID:</strong> {{ a.sid }}</p>
<p><strong>Timestamp:</strong> {{ a.timestamp }}</p>
<p><strong>Severity:</strong> {{ a.severity }}</p>
<p><strong>Source:</strong> {{ a.source }}</p>
<p><strong>Destination:</strong> {{ a.destination }}</p>
<p><strong>HTTP URI:</strong> {{ a.uri }}</p>
<p><strong>Evidence:</strong> {{ a.evidence }}</p>
</div>

<h2>Analyst Case Notes</h2>

<form method="post">

<div class="field">
<label for="status">Investigation Status</label>
<select name="status" id="status">
{% for value in statuses %}
<option value="{{ value }}"
{% if a.status == value %}selected{% endif %}>
{{ value }}
</option>
{% endfor %}
</select>
</div>

<div class="field">
<label for="disposition">Analyst Disposition</label>
<select name="disposition" id="disposition">
{% for value in dispositions %}
<option value="{{ value }}"
{% if a.disposition == value %}selected{% endif %}>
{{ value }}
</option>
{% endfor %}
</select>
</div>

<div class="field">
<label for="notes">Investigation Notes</label>
<textarea name="notes" id="notes"
placeholder="Document evidence, reasoning and outcome...">{{ a.notes }}</textarea>
</div>

<button type="submit">Save Investigation</button>

</form>

<p class="subtitle">
All updates are saved in dashboard/cases.db.
</p>

</body>
</html>
"""

@app.route("/alerts")
def dashboard():
    alerts = enrich_alerts()
    query = request.args.get("q", "").strip().lower()

    filtered = [
        a for a in alerts
        if not query or query in " ".join(
            str(v) for v in a.values()
        ).lower()
    ]

    counts = Counter(a["status"] for a in alerts)

    return render_template_string(
        INDEX_HTML,
        alerts=alerts,
        filtered=filtered,
        counts=counts,
        query=query,
    )

@app.route("/case/<path:alert_id>", methods=["GET", "POST"])
def case_detail(alert_id):
    alerts = enrich_alerts()
    alert = next((a for a in alerts if a["id"] == alert_id), None)

    if alert is None:
        abort(404)

    if request.method == "POST":
        status = request.form.get("status", "")
        disposition = request.form.get("disposition", "")
        notes = request.form.get("notes", "")

        if status not in STATUSES or disposition not in DISPOSITIONS:
            abort(400)

        with connect() as db:
            db.execute("""
                INSERT INTO cases (
                    alert_id, status, disposition, notes, updated_at
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(alert_id) DO UPDATE SET
                    status=excluded.status,
                    disposition=excluded.disposition,
                    notes=excluded.notes,
                    updated_at=CURRENT_TIMESTAMP
            """, (alert_id, status, disposition, notes))

        return redirect(url_for("case_detail", alert_id=alert_id))

    return render_template_string(
        CASE_HTML,
        a=alert,
        statuses=STATUSES,
        dispositions=DISPOSITIONS,
    )

init_db()



# === SOC LAB 06 SSH DETECTION INTEGRATION ===

from flask import abort as ssh_abort
from flask import redirect as ssh_redirect
from flask import request as ssh_request
from flask import url_for as ssh_url_for
from flask import render_template_string as ssh_render
import json as ssh_json
import sqlite3 as ssh_sqlite3

SSH_CASE_DB = (
    ROOT / "evidence/detection-staging.db"
)

SSH_LIST_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SOC — SOC Detection Queue</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #101820;
      color: #edf2f7;
      margin: 35px auto;
      max-width: 1100px;
    }
    a { color: #66c7ff; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 25px;
    }
    th, td {
      padding: 13px;
      text-align: left;
      border-bottom: 1px solid #344252;
    }
    th { color: #a7bacb; }
    .panel {
      padding: 20px;
      background: #1b2936;
      border-radius: 8px;
    }
  </style>
</head>
<body>

<!-- SOC_GLOBAL_NAV_V1 -->
<nav style="
  display:flex;
  gap:20px;
  flex-wrap:wrap;
  padding:14px 18px;
  margin-bottom:24px;
  background:#162236;
  border:1px solid #334155;
  border-radius:10px;
  font-family:Arial,sans-serif;
">
  <a href="/" style="color:#7dd3fc;">Overview</a>
  <a href="/investigations" style="color:#7dd3fc;">Investigations</a>
  <a href="/" style="color:#7dd3fc;">Suricata Alerts</a>
  <a href="/detections" style="color:#7dd3fc;">SOC Detections</a>
</nav>

  <p><a href="/">← Suricata Alert Queue</a></p>
  <h1>SOC Detection Queue</h1>
  <div class="panel">
    <p>Cases: {{ cases|length }}</p>
    <table>
      <tr>
        <th>Time</th>
        <th>Detection</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Disposition</th>
        <th>Action</th>
      </tr>
      {% for case in cases %}
      <tr>
        <td>{{ case["timestamp"] }}</td>
        <td>{{ case["title"] }}</td>
        <td>{{ case["severity"] }}</td>
        <td>{{ case["status"] }}</td>
        <td>{{ case["disposition"] }}</td>
        <td>
          <a href="{{ url_for('ssh_case_detail', case_id=case['id']) }}">
            Investigate
          </a>
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
</html>
"""

SSH_CASE_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SOC — SSH Investigation</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #101820;
      color: #edf2f7;
      margin: 35px auto;
      max-width: 850px;
    }
    a { color: #66c7ff; }
    .panel {
      background: #1b2936;
      padding: 22px;
      border-radius: 8px;
    }
    label {
      display: block;
      margin-top: 18px;
      margin-bottom: 6px;
    }
    select, textarea {
      width: 100%;
      box-sizing: border-box;
      padding: 10px;
      background: #101820;
      color: white;
      border: 1px solid #536779;
      border-radius: 5px;
    }
    textarea { min-height: 150px; }
    button {
      margin-top: 20px;
      padding: 12px 20px;
      background: #2878ae;
      color: white;
      border: 0;
      border-radius: 5px;
      cursor: pointer;
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #101820;
      padding: 15px;
    }
  </style>
</head>
<body>

<!-- SOC_GLOBAL_NAV_V1 -->
<nav style="
  display:flex;
  gap:20px;
  flex-wrap:wrap;
  padding:14px 18px;
  margin-bottom:24px;
  background:#162236;
  border:1px solid #334155;
  border-radius:10px;
  font-family:Arial,sans-serif;
">
  <a href="/" style="color:#7dd3fc;">Overview</a>
  <a href="/investigations" style="color:#7dd3fc;">Investigations</a>
  <a href="/" style="color:#7dd3fc;">Suricata Alerts</a>
  <a href="/detections" style="color:#7dd3fc;">SOC Detections</a>
</nav>

  <p><a href="/detections">← SOC Detection Queue</a></p>
  <h1>SSH Investigation</h1>

  <div class="panel">
    <h2>{{ case["title"] }}</h2>
    <p><strong>Case ID:</strong> {{ case["id"] }}</p>
    <p><strong>Severity:</strong> {{ case["severity"] }}</p>
    <p><strong>Timestamp:</strong> {{ case["timestamp"] }}</p>
    <p><strong>Source:</strong> {{ case["source"] }}</p>

    <h3>Detection Evidence</h3>
    <pre>{{ evidence }}</pre>

    <form method="post">
      <label for="status">Status</label>
      <select id="status" name="status">
        {% for option in statuses %}
        <option value="{{ option }}"
          {% if case["status"] == option %}selected{% endif %}>
          {{ option }}
        </option>
        {% endfor %}
      </select>

      <label for="disposition">Disposition</label>
      <select id="disposition" name="disposition">
        {% for option in dispositions %}
        <option value="{{ option }}"
          {% if case["disposition"] == option %}selected{% endif %}>
          {{ option }}
        </option>
        {% endfor %}
      </select>

      <label for="notes">Analyst Notes</label>
      <textarea id="notes" name="notes">{{ case["notes"] }}</textarea>

      <button type="submit">Save Investigation</button>
    </form>
  </div>
</body>
</html>
"""

@app.route("/detections")
def ssh_detection_queue():
    with ssh_sqlite3.connect(SSH_CASE_DB) as connection:
        connection.row_factory = ssh_sqlite3.Row
        cases = connection.execute("""
            SELECT * FROM detection_cases
            ORDER BY timestamp DESC
        """).fetchall()

    return ssh_render(
        SSH_LIST_TEMPLATE,
        cases=cases,
    )


@app.route("/detections/<case_id>", methods=["GET", "POST"])
def ssh_case_detail(case_id):
    statuses = ("New", "Investigating", "Closed")
    dispositions = (
        "Needs Investigation",
        "True Positive",
        "False Positive",
        "Benign True Positive",
    )

    with ssh_sqlite3.connect(SSH_CASE_DB) as connection:
        connection.row_factory = ssh_sqlite3.Row

        if ssh_request.method == "POST":
            status = ssh_request.form.get("status", "")
            disposition = ssh_request.form.get(
                "disposition", ""
            )
            notes = ssh_request.form.get("notes", "")

            if (
                status not in statuses
                or disposition not in dispositions
            ):
                ssh_abort(400)

            cursor = connection.execute("""
                UPDATE detection_cases
                SET status = ?, disposition = ?, notes = ?
                WHERE id = ?
            """, (status, disposition, notes, case_id))

            if cursor.rowcount == 0:
                ssh_abort(404)

            connection.commit()

            return ssh_redirect(
                ssh_url_for(
                    "ssh_case_detail",
                    case_id=case_id,
                )
            )

        case = connection.execute("""
            SELECT * FROM detection_cases
            WHERE id = ?
        """, (case_id,)).fetchone()

    if case is None:
        ssh_abort(404)

    evidence = ssh_json.dumps(
        ssh_json.loads(case["evidence"]),
        indent=2,
    )

    return ssh_render(
        SSH_CASE_TEMPLATE,
        case=case,
        evidence=evidence,
        statuses=statuses,
        dispositions=dispositions,
    )

# SOC_UNIFIED_OVERVIEW_V1

@app.route("/")
@app.route("/overview")
def soc_unified_overview():
    import sqlite3
    from pathlib import Path
    from flask import render_template_string

    suricata_db = Path.home() / "SOC-Lab-03/dashboard/cases.db"
    detection_db = Path.home() / "SOC-Lab-06/evidence/detection-staging.db"

    sources = []

    with sqlite3.connect(suricata_db) as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) FROM cases GROUP BY status"
        ).fetchall()

    sources.append({
        "name": "Suricata IDS",
        "url": "/alerts",
        "counts": dict(rows),
    })

    with sqlite3.connect(detection_db) as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) FROM detection_cases GROUP BY status"
        ).fetchall()

    sources.append({
        "name": "SSH and Endpoint Detections",
        "url": "/detections",
        "counts": dict(rows),
    })

    for source in sources:
        source["total"] = sum(source["counts"].values())
        source["closed"] = sum(
            count
            for status, count in source["counts"].items()
            if status.strip().lower() == "closed"
        )
        source["open"] = source["total"] - source["closed"]

    total = sum(source["total"] for source in sources)
    closed = sum(source["closed"] for source in sources)
    opened = total - closed

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>SOC Unified Overview</title>
      <style>
        body {
          background: #0b1220;
          color: #e5e7eb;
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 32px;
        }
        main { max-width: 1000px; margin: auto; }
        h1 { margin-bottom: 8px; }
        p { color: #94a3b8; }
        .stats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
          margin: 28px 0;
        }
        .stat, .source {
          background: #162236;
          border: 1px solid #334155;
          border-radius: 12px;
          padding: 22px;
        }
        .number {
          font-size: 36px;
          font-weight: bold;
          margin-top: 12px;
        }
        .label { color: #94a3b8; }
        .closed { color: #4ade80; }
        .source { margin-bottom: 14px; }
        a { color: #7dd3fc; }
        @media (max-width: 600px) {
          .stats { grid-template-columns: 1fr; }
        }
      </style>
    </head>
    <body>

<!-- SOC_GLOBAL_NAV_V1 -->
<nav style="
  display:flex;
  gap:20px;
  flex-wrap:wrap;
  padding:14px 18px;
  margin-bottom:24px;
  background:#162236;
  border:1px solid #334155;
  border-radius:10px;
  font-family:Arial,sans-serif;
">
  <a href="/" style="color:#7dd3fc;">Overview</a>
  <a href="/investigations" style="color:#7dd3fc;">Investigations</a>
  <a href="/" style="color:#7dd3fc;">Suricata Alerts</a>
  <a href="/detections" style="color:#7dd3fc;">SOC Detections</a>
</nav>

      <main>
        <h1>SOC Investigation Overview</h1>
        <p>Unified case statistics across Suricata, SSH, and endpoint detections.</p>

        <div class="stats">
          <div class="stat">
            <div class="label">Total Cases</div>
            <div class="number">{{ total }}</div>
          </div>
          <div class="stat">
            <div class="label">Closed Cases</div>
            <div class="number closed">{{ closed }}</div>
          </div>
          <div class="stat">
            <div class="label">Open Cases</div>
            <div class="number">{{ opened }}</div>
          </div>
        </div>

        <h2>Detection Sources</h2>

        {% for source in sources %}
        <div class="source">
          <h3>{{ source.name }}</h3>
          <p>
            Total: {{ source.total }} |
            Closed: {{ source.closed }} |
            Open: {{ source.open }}
          </p>
          <a href="{{ source.url }}">Open investigation queue →</a>
        </div>
        {% endfor %}

        <p>Case counts are read directly from both SQLite databases.</p>
      </main>
    </body>
    </html>
    """, total=total, closed=closed, opened=opened, sources=sources)



# SOC_LAB08_UNIFIED_QUEUE_V1
@app.route("/investigations")
def unified_investigation_queue():
    import json
    import sqlite3
    from pathlib import Path
    from urllib.parse import quote
    from flask import request, render_template_string

    home = Path.home()
    lab03 = home / "SOC-Lab-03"
    suricata_db = lab03 / "dashboard/cases.db"
    detection_db = home / "SOC-Lab-06/evidence/detection-staging.db"

    cases = []

    def read_db(path, query):
        if not path.exists():
            raise FileNotFoundError(str(path))
        with sqlite3.connect(
            "file:" + str(path) + "?mode=ro",
            uri=True
        ) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(query)]

    def load_suricata_alert(alert_id):
        try:
            relative_path, line_number = alert_id.rsplit(":", 1)
            path = (lab03 / relative_path).resolve()

            if not path.is_relative_to(lab03.resolve()):
                return {}

            if not path.is_file():
                return {}

            target = int(line_number)
            if target < 1:
                return {}

            with path.open(encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if number == target:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            return event
                        return {}
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return {}

    for record in read_db(
        suricata_db,
        "SELECT alert_id, status, disposition, updated_at "
        "FROM cases"
    ):
        alert = load_suricata_alert(record["alert_id"])
        metadata = alert.get("alert", {})

        severity_number = metadata.get("severity")
        severity = {
            1: "High",
            2: "Medium",
            3: "Low"
        }.get(severity_number, "Unknown")

        cases.append({
            "id": record["alert_id"],
            "title": metadata.get(
                "signature", "Suricata IDS Alert"
            ),
            "source": "Suricata IDS",
            "severity": severity,
            "status": record["status"] or "New",
            "disposition": record["disposition"] or "",
            "timestamp": alert.get(
                "timestamp", record["updated_at"] or ""
            ),
            "url": "/case/" + quote(
                record["alert_id"], safe=""
            )
        })

    for record in read_db(
        detection_db,
        "SELECT id, title, severity, timestamp, source, "
        "status, disposition FROM detection_cases"
    ):
        source_text = record["source"] or ""
        category = (
            "Endpoint / auditd"
            if record["id"].startswith("endpoint-")
            else "SSH Authentication"
            if record["id"].startswith("ssh-")
            else source_text or "Detection"
        )

        cases.append({
            "id": record["id"],
            "title": record["title"] or record["id"],
            "source": category,
            "severity": (
                record["severity"] or "Unknown"
            ).capitalize(),
            "status": record["status"] or "New",
            "disposition": record["disposition"] or "",
            "timestamp": record["timestamp"] or "",
            "url": "/detections/" + quote(
                record["id"], safe=""
            )
        })

    # SOC_CAPSTONE_QUEUE_V1
    capstone = load_capstone()
    if capstone:
        cases.append({
            key: capstone[key]
            for key in (
                "id", "title", "source", "severity",
                "status", "disposition", "timestamp", "url"
            )
        })

    search = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "all")
    severity_filter = request.args.get("severity", "all")

    total = len(cases)
    open_count = sum(
        str(item["status"]).lower() != "closed"
        for item in cases
    )

    filtered = []
    for item in cases:
        searchable = " ".join(
            str(item[key]) for key in (
                "id", "title", "source", "disposition"
            )
        ).lower()

        if search and search.lower() not in searchable:
            continue

        if (
            status_filter != "all"
            and item["status"].lower() != status_filter.lower()
        ):
            continue

        if (
            severity_filter != "all"
            and item["severity"].lower() != severity_filter.lower()
        ):
            continue

        filtered.append(item)

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Unknown": 4
    }

    filtered.sort(
        key=lambda item: (
            item["status"].lower() == "closed",
            severity_order.get(item["severity"], 4),
            item["title"].lower()
        )
    )

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport"
            content="width=device-width, initial-scale=1">
      <title>Unified Investigations | SOC</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0;
          background: #0b1220;
          color: #e2e8f0;
          font-family: Arial, sans-serif;
        }
        .shell {
          max-width: 1250px;
          margin: auto;
          padding: 30px 20px;
        }
        nav {
          display: flex;
          flex-wrap: wrap;
          gap: 22px;
          padding: 18px 20px;
          background: #162236;
          border: 1px solid #334155;
          border-radius: 12px;
          margin-bottom: 30px;
        }
        a { color: #7dd3fc; }
        h1 { margin-bottom: 6px; }
        .muted { color: #94a3b8; }
        .stats {
          display: flex;
          gap: 14px;
          flex-wrap: wrap;
          margin: 24px 0;
        }
        .stat {
          background: #162236;
          border: 1px solid #334155;
          border-radius: 10px;
          padding: 18px 22px;
          min-width: 160px;
        }
        .stat strong {
          display: block;
          font-size: 30px;
          margin-top: 8px;
        }
        .panel {
          background: #162236;
          border: 1px solid #334155;
          border-radius: 12px;
          overflow: hidden;
        }
        form {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          padding: 20px;
        }
        input, select, button {
          background: #0b1220;
          color: #e2e8f0;
          border: 1px solid #475569;
          border-radius: 8px;
          padding: 11px;
          font-size: 14px;
        }
        input { flex: 1; min-width: 200px; }
        button {
          background: #0369a1;
          cursor: pointer;
          border-color: #0284c7;
        }
        .table-wrap { overflow-x: auto; }
        table {
          width: 100%;
          border-collapse: collapse;
          min-width: 800px;
        }
        th, td {
          padding: 15px;
          border-top: 1px solid #334155;
          text-align: left;
          font-size: 14px;
        }
        th {
          color: #94a3b8;
          font-size: 12px;
          text-transform: uppercase;
        }
        tr:hover td { background: #1e293b; }
        .pill {
          display: inline-block;
          padding: 5px 10px;
          border-radius: 999px;
          background: #334155;
          font-size: 12px;
          font-weight: bold;
        }
        .high { color: #fca5a5; }
        .medium { color: #fcd34d; }
        .low { color: #86efac; }
        .case-title {
          font-weight: bold;
          text-decoration: none;
        }
        .case-id {
          font-size: 11px;
          margin-top: 5px;
          word-break: break-all;
        }
        .footer {
          padding: 18px 20px;
          color: #94a3b8;
          font-size: 13px;
        }
      </style>
    </head>
    <body>
      <div class="shell">
        <nav>
          <a href="/">Overview</a>
          <a href="/investigations">Investigations</a>
          <a href="/alerts">Suricata Alerts</a>
          <a href="/detections">SOC Detections</a>
        </nav>

        <h1>Unified Investigation Queue</h1>
        <p class="muted">
          Suricata IDS, SSH authentication, endpoint detections, and simulated capstone investigations in one analyst workspace.
        </p>

        <div class="stats">
          <div class="stat">
            <span class="muted">Total cases</span>
            <strong>{{ total }}</strong>
          </div>
          <div class="stat">
            <span class="muted">Open cases</span>
            <strong>{{ open_count }}</strong>
          </div>
          <div class="stat">
            <span class="muted">Matching cases</span>
            <strong>{{ filtered|length }}</strong>
          </div>
        </div>

        <div class="panel">
          <form method="get" action="/investigations">
            <input
              name="q"
              placeholder="Search title, source, case ID..."
              value="{{ search }}"
            >

            <select name="status">
              {% for option in
                 ["all", "New", "Investigating", "Closed"] %}
              <option value="{{ option }}"
                {% if status_filter|lower == option|lower %}
                selected{% endif %}>
                {{ option|title }}
              </option>
              {% endfor %}
            </select>

            <select name="severity">
              {% for option in
                 ["all", "Critical", "High", "Medium",
                  "Low", "Unknown"] %}
              <option value="{{ option }}"
                {% if severity_filter|lower == option|lower %}
                selected{% endif %}>
                {{ option|title }}
              </option>
              {% endfor %}
            </select>

            <button type="submit">Apply filters</button>
            <a href="/investigations"
               style="align-self:center">Reset</a>
          </form>

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Investigation</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Disposition</th>
                  <th>Event time</th>
                </tr>
              </thead>
              <tbody>
                {% for item in filtered %}
                <tr>
                  <td>
                    <a class="case-title"
                       href="{{ item.url }}">
                      {{ item.title }}
                    </a>
                    <div class="muted case-id">
                      {{ item.id }}
                    </div>
                  </td>
                  <td>{{ item.source }}</td>
                  <td>
                    <span class="pill
                      {{ item.severity|lower }}">
                      {{ item.severity }}
                    </span>
                  </td>
                  <td>
                    <span class="pill">
                      {{ item.status }}
                    </span>
                  </td>
                  <td>{{ item.disposition or "—" }}</td>
                  <td>{{ item.timestamp or "—" }}</td>
                </tr>
                {% else %}
                <tr>
                  <td colspan="6" class="muted">
                    No cases match the selected filters.
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>

          <div class="footer">
            Showing {{ filtered|length }} of {{ total }}
            cases. Case data comes from local SQLite investigation databases and capstone JSON evidence.
          </div>
        </div>
      </div>
    </body>
    </html>
    """,
    total=total,
    open_count=open_count,
    filtered=filtered,
    search=search,
    status_filter=status_filter,
    severity_filter=severity_filter)



# SOC_OVERVIEW_V2_ROUTE
from soc_overview_v2 import render_overview as soc_render_overview_v2

app.add_url_rule(
    "/soc-command-center",
    endpoint="soc_command_center_v2",
    view_func=soc_render_overview_v2
)

for _soc_rule in app.url_map.iter_rules():
    if _soc_rule.rule in ("/", "/overview"):
        _soc_rule.endpoint = "soc_command_center_v2"


# SOC_CAPSTONE_INTEGRATION_V1
from soc_capstone import load_capstone, capstone_detail

app.add_url_rule(
    "/capstone/CAPSTONE-001",
    endpoint="capstone_detail",
    view_func=capstone_detail
)


# SOC_COMMAND_V3_START
from soc_command_v3 import overview as _soc_v3_overview, investigations as _soc_v3_investigations, quality as _soc_v3_quality, capstone as _soc_v3_capstone
app.add_url_rule('/quality', endpoint='soc_v3_quality', view_func=_soc_v3_quality)
app.add_url_rule('/soc-v3', endpoint='soc_v3_overview', view_func=_soc_v3_overview)
app.add_url_rule('/soc-v3/investigations', endpoint='soc_v3_investigations', view_func=_soc_v3_investigations)
app.add_url_rule('/soc-v3/capstone', endpoint='soc_v3_capstone', view_func=_soc_v3_capstone)
for _soc_v3_rule in app.url_map.iter_rules():
    if _soc_v3_rule.rule in ('/', '/overview', '/soc-command-center'):
        _soc_v3_rule.endpoint = 'soc_v3_overview'
    elif _soc_v3_rule.rule == '/investigations':
        _soc_v3_rule.endpoint = 'soc_v3_investigations'
    elif _soc_v3_rule.rule == '/capstone/CAPSTONE-001':
        _soc_v3_rule.endpoint = 'soc_v3_capstone'
# SOC_COMMAND_V3_END


# SOC_COMMAND_V31_START
from soc_v31_legacy import adapt as _soc_v31_adapt
app.after_request(_soc_v31_adapt)
# SOC_COMMAND_V31_END

if __name__ == "__main__":
    print("SOC Investigation Console: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
