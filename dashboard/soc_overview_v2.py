
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from flask import render_template_string
from soc_capstone import load_capstone

HOME = Path.home()
LAB03 = Path(__file__).resolve().parent.parent
SURICATA_DB = LAB03 / "dashboard/cases.db"
DETECTION_DB = LAB03 / "evidence/detection-staging.db"

SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")

def read_rows(path, query):
    if not path.is_file():
        raise FileNotFoundError(str(path))
    with sqlite3.connect(
        "file:" + str(path) + "?mode=ro", uri=True
    ) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query)]

def eve_alert(alert_id):
    try:
        relative, line_number = alert_id.rsplit(":", 1)
        path = (LAB03 / relative).resolve()
        if not path.is_relative_to(LAB03.resolve()):
            return {}
        number = int(line_number)
        if number < 1:
            return {}
        with path.open(encoding="utf-8") as handle:
            for index, line in enumerate(handle, 1):
                if index == number:
                    event = json.loads(line)
                    return event if event.get("event_type") == "alert" else {}
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return {}

def collect_cases():
    cases = []
    health = []

    sources = [
        ("Suricata IDS", SURICATA_DB),
        ("SSH / Endpoint", DETECTION_DB)
    ]

    for name, path in sources:
        health.append({
            "name": name,
            "ok": path.is_file(),
            "path": str(path)
        })

    if SURICATA_DB.is_file():
        try:
            records = read_rows(
                SURICATA_DB,
                "SELECT alert_id, status, disposition, updated_at FROM cases"
            )
            for row in records:
                event = eve_alert(row["alert_id"])
                alert = event.get("alert", {})
                severity = {
                    1: "High", 2: "Medium", 3: "Low"
                }.get(alert.get("severity"), "Unknown")
                cases.append({
                    "title": alert.get("signature", "Suricata IDS Alert"),
                    "source": "Suricata IDS",
                    "severity": severity,
                    "status": row["status"] or "New",
                    "disposition": row["disposition"] or "",
                    "time": event.get("timestamp") or row["updated_at"] or "",
                    "url": "/case/" + quote(row["alert_id"], safe="")
                })
        except (sqlite3.Error, OSError) as exc:
            health[0]["ok"] = False
            health[0]["error"] = str(exc)

    if DETECTION_DB.is_file():
        try:
            records = read_rows(
                DETECTION_DB,
                "SELECT id, title, severity, timestamp, status, disposition "
                "FROM detection_cases"
            )
            for row in records:
                source = (
                    "Endpoint / auditd"
                    if row["id"].startswith("endpoint-")
                    else "SSH Authentication"
                    if row["id"].startswith("ssh-")
                    else "Other Detection"
                )
                cases.append({
                    "title": row["title"] or row["id"],
                    "source": source,
                    "severity": (row["severity"] or "Unknown").capitalize(),
                    "status": row["status"] or "New",
                    "disposition": row["disposition"] or "",
                    "time": row["timestamp"] or "",
                    "url": "/detections/" + quote(row["id"], safe="")
                })
        except (sqlite3.Error, OSError) as exc:
            health[1]["ok"] = False
            health[1]["error"] = str(exc)

    # SOC_CAPSTONE_OVERVIEW_V1
    capstone_path = (
        HOME / "SOC-Capstone/evidence/response-decision.json"
    )
    capstone_health = {
        "name": "Capstone Investigation",
        "ok": False,
        "path": str(capstone_path)
    }

    try:
        capstone = load_capstone()

        if capstone is not None:
            cases.append({
                "title": capstone["title"],
                "source": capstone["source"],
                "severity": capstone["severity"],
                "status": capstone["status"],
                "disposition": capstone["disposition"],
                "time": capstone["timestamp"],
                "url": capstone["url"]
            })
            capstone_health["ok"] = True
        else:
            capstone_health["error"] = "Capstone evidence missing"
    except (OSError, ValueError, KeyError) as exc:
        capstone_health["error"] = str(exc)

    health.append(capstone_health)

    return cases, health


# SOC_TIMESTAMP_SORT_V1
from datetime import datetime, timezone

def soc_timestamp_key(value):
    if not value:
        return float("-inf")

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, TypeError, OverflowError):
        return float("-inf")

def render_overview():
    cases, health = collect_cases()
    total = len(cases)
    open_cases = [
        case for case in cases
        if case["status"].strip().lower() != "closed"
    ]
    closed = total - len(open_cases)
    escalated = sum(
        case["status"].strip().lower() == "escalated"
        for case in cases
    )

    severity_counts = {
        severity: sum(
            case["severity"] == severity for case in cases
        )
        for severity in SEVERITIES
    }

    priority = {
        "Critical": 0, "High": 1, "Medium": 2,
        "Low": 3, "Unknown": 4
    }

    open_cases.sort(
        key=lambda case: (
            priority.get(case["severity"], 4),
            case["time"]
        )
    )
    recent = sorted(
        cases,
        key=lambda case: soc_timestamp_key(case["time"]),
        reverse=True
    )[:5]

    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Command Center</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #0b1220;
  color: #e2e8f0;
  font-family: Arial, sans-serif;
}
.shell { max-width: 1240px; margin: auto; padding: 30px 22px; }
nav {
  display: flex; gap: 22px; flex-wrap: wrap;
  background: #162236; border: 1px solid #334155;
  border-radius: 12px; padding: 18px 22px; margin-bottom: 28px;
}
a { color: #7dd3fc; }
h1 { margin: 0 0 8px; font-size: 30px; }
h2 { margin-top: 0; font-size: 19px; }
.muted { color: #94a3b8; }
.stats {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 15px; margin: 25px 0;
}
.card, .panel {
  background: #162236; border: 1px solid #334155;
  border-radius: 12px; padding: 21px;
}
.value { font-size: 36px; font-weight: bold; margin-top: 12px; }
.green { color: #4ade80; }
.amber { color: #fbbf24; }
.red { color: #fca5a5; }
.columns {
  display: grid; grid-template-columns: 1.4fr 1fr;
  gap: 16px; margin-bottom: 16px;
}
.panel { min-width: 0; }
.item {
  padding: 14px 0; border-top: 1px solid #334155;
}
.item:first-of-type { border-top: 0; }
.item a { font-weight: bold; text-decoration: none; }
.meta { font-size: 12px; margin-top: 7px; color: #94a3b8; }
.bar {
  height: 10px; background: #334155;
  border-radius: 10px; overflow: hidden; margin-top: 8px;
}
.fill { height: 100%; background: #38bdf8; }
.severity { margin-bottom: 16px; }
.row {
  display: flex; justify-content: space-between;
  align-items: center; gap: 10px;
}
.pill {
  display: inline-block; border-radius: 999px;
  background: #334155; padding: 5px 10px;
  font-size: 12px;
}
@media (max-width: 800px) {
  .stats { grid-template-columns: repeat(2, 1fr); }
  .columns { grid-template-columns: 1fr; }
}
@media (max-width: 450px) {
  .stats { grid-template-columns: 1fr; }
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

<h1>SOC Command Center</h1>
<p class="muted">
  Unified analyst overview · Historical lab investigations
</p>

<div class="stats">
  <div class="card">
    <div class="muted">Total Cases</div>
    <div class="value">{{ total }}</div>
  </div>
  <div class="card">
    <div class="muted">Open Cases</div>
    <div class="value {% if open_cases %}amber{% else %}green{% endif %}">
      {{ open_cases|length }}
    </div>
  </div>
  <div class="card">
    <div class="muted">Closed Cases</div>
    <div class="value green">{{ closed }}</div>
  </div>
  <div class="card">
    <div class="muted">High / Critical Cases</div>
    <div class="value red">
      {{ severity_counts.High + severity_counts.Critical }}
    </div>
    <div class="meta">All statuses, including closed</div>
  </div>
</div>

<div class="columns">
  <section class="panel">
    <div class="row">
      <h2>Action Required ({{ escalated }} escalated)</h2>
      <a href="/investigations">View queue →</a>
    </div>
    {% for case in open_cases[:5] %}
    <div class="item">
      <a href="{{ case.url }}">{{ case.title }}</a>
      <div class="meta">
        {{ case.source }} · {{ case.severity }} · {{ case.status }}
      </div>
    </div>
    {% else %}
    <div class="item">
      <span class="green">No open investigations</span>
      <div class="meta">
        All currently recorded cases have been closed.
      </div>
    </div>
    {% endfor %}
  </section>

  <section class="panel">
    <h2>Severity Distribution</h2>
    {% for severity, count in severity_counts.items() %}
    <div class="severity">
      <div class="row">
        <span>{{ severity }}</span>
        <span>{{ count }}</span>
      </div>
      <div class="bar">
        <div class="fill"
          style="width:{{ (count / total * 100) if total else 0 }}%">
        </div>
      </div>
    </div>
    {% endfor %}
    <div class="meta">Based on all recorded cases.</div>
  </section>
</div>

<div class="columns">
  <section class="panel">
    <div class="row">
      <h2>Recent Investigations</h2>
      <a href="/investigations">View all →</a>
    </div>
    {% for case in recent %}
    <div class="item">
      <a href="{{ case.url }}">{{ case.title }}</a>
      <div class="meta">
        {{ case.source }} · {{ case.severity }} ·
        {{ case.status }} · {{ case.time }}
      </div>
    </div>
    {% endfor %}
  </section>

  <section class="panel">
    <h2>Case Data Sources</h2>
    {% for source in health %}
    <div class="item">
      <div class="row">
        <strong>{{ source.name }}</strong>
        {% if source.ok %}
        <span class="pill green">Readable</span>
        {% else %}
        <span class="pill red">Unavailable</span>
        {% endif %}
      </div>
      {% if source.error %}
      <div class="meta">{{ source.error }}</div>
      {% endif %}
    </div>
    {% endfor %}
    <p class="meta">
      Health reflects case database access, not live sensor
      or ingestion status.
    </p>
  </section>
</div>
</div>
</body>
</html>
""",
        total=total,
        closed=closed,
        escalated=escalated,
        open_cases=open_cases,
        severity_counts=severity_counts,
        recent=recent,
        health=health
    )
