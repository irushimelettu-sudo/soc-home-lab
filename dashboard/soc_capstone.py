
import json
from pathlib import Path
from flask import render_template_string, abort

ROOT = Path(__file__).resolve().parent.parent / "capstone"
EVIDENCE = ROOT / "evidence"
REPORT = ROOT / "reports/capstone-investigation.md"

def load_capstone():
    decision_path = EVIDENCE / "response-decision.json"
    timeline_path = EVIDENCE / "unified-timeline.json"

    if not decision_path.is_file() or not timeline_path.is_file():
        return None

    decision = json.loads(decision_path.read_text())
    timeline = json.loads(timeline_path.read_text())

    return {
        "id": decision["case_id"],
        "title": "Suspected SSH Account Compromise and Script Retrieval",
        "source": "Capstone Investigation (Simulation)",
        "severity": "High",
        "status": "Escalated",
        "disposition": "Compromise Unconfirmed",
        "timestamp": timeline[0]["timestamp"] if timeline else "",
        "url": "/capstone/CAPSTONE-001",
        "decision": decision,
        "timeline": timeline,
    }

def capstone_detail():
    case = load_capstone()

    if case is None:
        abort(404)

    report = REPORT.read_text() if REPORT.exists() else ""

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{{ case.id }} | SOC Investigation</title>
      <style>
        body {
          background: #0b1220;
          color: #e2e8f0;
          font-family: Arial, sans-serif;
          margin: 0;
        }
        main { max-width: 1100px; margin: auto; padding: 28px; }
        nav { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 28px; }
        a { color: #7dd3fc; }
        .panel {
          background: #162236;
          border: 1px solid #334155;
          border-radius: 12px;
          padding: 22px;
          margin-bottom: 18px;
        }
        .muted { color: #94a3b8; }
        .high { color: #fca5a5; }
        .status { color: #fbbf24; }
        pre {
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          line-height: 1.6;
          font-family: inherit;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td {
          padding: 12px;
          border-bottom: 1px solid #334155;
          text-align: left;
          vertical-align: top;
        }
      </style>
    </head>
    <body>
    <main>
      <nav>
        <a href="/">Overview</a>
        <a href="/investigations">Investigations</a>
        <a href="/alerts">Suricata Alerts</a>
        <a href="/detections">SOC Detections</a>
      </nav>

      <h1>{{ case.id }}</h1>
      <p>{{ case.title }}</p>

      <div class="panel">
        <h2>Investigation Summary</h2>
        <p><strong>Severity:</strong>
          <span class="high">{{ case.severity }} — provisional</span></p>
        <p><strong>Status:</strong>
          <span class="status">{{ case.status }}</span></p>
        <p><strong>Disposition:</strong> {{ case.disposition }}</p>
        <p><strong>Environment:</strong> Authorized simulation</p>
        <p><strong>Escalation:</strong> {{ case.decision.escalation }}</p>
        <p><strong>Compromise confirmed:</strong> No</p>
        <p class="muted">
          The exercise is complete. The simulated investigation
          remains unresolved pending additional evidence.
        </p>
      </div>

      <div class="panel">
        <h2>Unified Evidence Timeline</h2>
        <table>
          <tr><th>Time (UTC)</th><th>Source</th><th>Event</th></tr>
          {% for event in case.timeline %}
          <tr>
            <td>{{ event.timestamp }}</td>
            <td>{{ event.source }}</td>
            <td>{{ event.description }}</td>
          </tr>
          {% endfor %}
        </table>
      </div>

      <div class="panel">
        <h2>Investigation Report</h2>
        <pre>{{ report }}</pre>
      </div>
    </main>
    </body>
    </html>
    """, case=case, report=report)
