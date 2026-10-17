"""SOC Command v3: read-only analyst views over existing SOC lab data."""
from collections import Counter
from datetime import datetime, timezone
from markupsafe import Markup, escape
from pathlib import Path
import json
from flask import render_template_string, request
from soc_overview_v2 import collect_cases
from soc_capstone import load_capstone

HOME = Path.home()
QUALITY = Path(__file__).resolve().parent.parent / 'validation/detection-quality.json'

CSS = '''
:root{color-scheme:dark;--bg:#080f1d;--panel:#121e31;--panel2:#17263d;--line:#2a3b53;--text:#e8effa;--muted:#9fb0c6;--cyan:#67d9ed;--red:#ff8396;--amber:#f6c76b;--green:#72deb2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid var(--cyan);outline-offset:3px}
.shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}.side{background:#0d192a;border-right:1px solid var(--line);padding:27px 18px}.brand{font-weight:850;letter-spacing:.12em;font-size:17px}.brand b{color:var(--cyan)}.sub{font-size:12px;color:var(--muted);margin:8px 0 28px}.nav a{display:block;padding:11px 13px;border-radius:9px;color:#bac8db;margin:5px 0}.nav a.active,.nav a:hover{background:#1c3248;color:white;text-decoration:none}.side-note{margin-top:36px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:18px}
main{max-width:1500px;width:100%;padding:35px 42px;margin:auto}.eyebrow{text-transform:uppercase;letter-spacing:.17em;font-size:11px;color:var(--cyan);font-weight:750}h1{font-size:clamp(26px,3vw,38px);line-height:1.15;margin:9px 0 12px}h2{font-size:17px;margin:0 0 17px}p{color:var(--muted)}.head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:24px}.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#1b2a40;border-radius:100px;padding:4px 10px;font-size:12px;white-space:nowrap}.pill.high,.pill.critical{color:var(--red);border-color:#713c51}.pill.escalated,.pill.new{color:var(--amber);border-color:#6b5538}.pill.closed{color:var(--green);border-color:#2f6559}.pill.medium{color:var(--amber)}.pill.low{color:#8ec7ff}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:20px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:21px;min-width:0}.metric .num{font-size:38px;line-height:1.1;font-weight:800;margin-top:12px}.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:16px;margin:16px 0}.grid2.equal{grid-template-columns:1fr 1fr}.callout{border-left:4px solid var(--amber);background:#1c2939}.muted{color:var(--muted)}.small{font-size:12px}.strong{font-weight:750}.case-title{font-size:19px;font-weight:750;margin:8px 0}.action{display:inline-block;background:var(--cyan);color:#061522;font-weight:800;padding:10px 15px;border-radius:9px;margin-top:12px}.action:hover{color:#061522}.barrow{display:grid;grid-template-columns:80px 1fr 26px;align-items:center;gap:12px;margin:14px 0}.bar{background:#26364b;height:9px;border-radius:30px;overflow:hidden}.bar>span{display:block;height:100%;background:var(--cyan)}.health{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding:11px 0}.health:last-child{border-bottom:0}.ok{color:var(--green)}.bad{color:var(--red)}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:720px}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}td,th{padding:14px 11px;border-bottom:1px solid var(--line);vertical-align:top}td{font-size:13px}td:first-child{max-width:420px}tr:hover td{background:#17263a}.filters{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.filters input,.filters select{background:#0c1728;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px 12px;font:inherit}.filters input{min-width:240px;flex:1}.filters button{background:var(--cyan);border:0;border-radius:9px;padding:10px 17px;font-weight:800;cursor:pointer}.timeline{border-left:2px solid var(--line);padding-left:22px;margin-left:9px}.event{position:relative;margin:0 0 22px}.event:before{content:'';position:absolute;left:-29px;top:7px;width:10px;height:10px;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 4px var(--panel)}.event .time{font-size:12px;color:var(--muted)}.event .desc{margin-top:5px;overflow-wrap:anywhere}.report{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.7 ui-monospace,monospace;max-height:650px;overflow:auto}.qualitygrid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.qualitygrid .num{font-size:30px;font-weight:800}.foot{font-size:12px;color:var(--muted);margin:28px 0 0}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid var(--line);padding:15px}.side-note{display:none}.nav{display:flex;flex-wrap:wrap;gap:3px}.nav a{padding:8px}.sub{margin:4px 0 8px}main{padding:22px}.metrics{grid-template-columns:repeat(2,1fr)}.grid2,.grid2.equal{grid-template-columns:1fr}}@media(max-width:500px){.metrics,.qualitygrid{grid-template-columns:1fr 1fr}.head{display:block}.card{padding:16px}}
'''

CSS += '''
.legacy-content h1{margin:8px 0 10px}.legacy-content h2{margin:24px 0 15px}.legacy-content h3{margin:18px 0 10px}.legacy-content .subtitle{color:var(--muted)}
.legacy-content .cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:24px 0}.legacy-content .cards .card{background:var(--panel)}.legacy-content .number{font-size:34px;font-weight:800;color:var(--cyan)}.legacy-content .label{font-size:12px;color:var(--muted)}
.legacy-content .panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;max-width:none}.legacy-content .table-wrap{overflow-x:auto}.legacy-content table{min-width:720px}.legacy-content form{max-width:100%}.legacy-content input,.legacy-content select,.legacy-content textarea{background:#0c1728;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px;font:inherit;max-width:100%}.legacy-content textarea{width:100%;min-height:140px}.legacy-content button{background:var(--cyan);color:#061522;border:0;border-radius:9px;padding:11px 18px;font-weight:800;cursor:pointer}.legacy-content label{display:block;margin:13px 0 7px}.legacy-content .field{margin:15px 0}.legacy-content pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1627;padding:16px;border-radius:10px;border:1px solid var(--line);max-height:520px;overflow:auto}.legacy-content p{overflow-wrap:anywhere}.legacy-content td{overflow-wrap:anywhere}.legacy-content .panel > p:first-child{color:var(--muted)}
.legacy-content .legacy-back{margin-bottom:16px}.legacy-content .legacy-head{margin-bottom:25px}.legacy-content .legacy-head h1{margin:7px 0}.legacy-content .legacy-head p{margin:0}.legacy-content .legacy-nav{display:none}
@media(max-width:900px){.legacy-content .cards{grid-template-columns:repeat(2,1fr)}}
'''

BASE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · SOC Command</title><style>''' + CSS + '''</style></head><body><div class="shell"><aside class="side"><div class="brand">◈ SOC <b>COMMAND</b></div><div class="sub">Analyst workspace · Local lab</div><nav class="nav" aria-label="Primary navigation"><a class="{{ 'active' if active=='overview' else '' }}" href="/">◫ &nbsp; Command center</a><a class="{{ 'active' if active=='investigations' else '' }}" href="/investigations">▤ &nbsp; Investigations</a><a class="{{ 'active' if active=='quality' else '' }}" href="/quality">◇ &nbsp; Detection quality</a><a class="{{ 'active' if active=='alerts' else '' }}" href="/alerts">◉ &nbsp; Suricata triage</a><a class="{{ 'active' if active=='detections' else '' }}" href="/detections">⌁ &nbsp; Detection staging</a></nav><div class="side-note">SIMULATED TRAINING ENVIRONMENT<br>Case data is historical. Readable evidence is not a live sensor-health check.</div></aside><main>{{ body|safe }}<div class="foot">SOC training portfolio · Existing SQLite case decisions and JSON evidence are read-only in this view.</div></main></div></body></html>'''

OVERVIEW = '''<div class="head"><div><div class="eyebrow">Operations overview</div><h1>SOC Command Center</h1><p>Prioritized investigations, evidence sources, and detection assurance.</p></div><span class="pill">TRAINING LAB · HISTORICAL DATA</span></div>
<div class="metrics"><div class="card metric"><div class="label">Total investigations</div><div class="num">{{ total }}</div><div class="muted small">All recorded cases</div></div><div class="card metric"><div class="label">Action required</div><div class="num" style="color:var(--amber)">{{ open_count }}</div><div class="muted small">Not closed</div></div><div class="card metric"><div class="label">Closed</div><div class="num" style="color:var(--green)">{{ closed }}</div><div class="muted small">Analyst decisions recorded</div></div><div class="card metric"><div class="label">High / critical</div><div class="num">{{ high }}</div><div class="muted small">Across all statuses</div></div></div>
<div class="grid2"><section class="card callout"><div class="eyebrow">Priority queue</div><h2 style="margin-top:8px">{{ open_count }} case(s) awaiting review</h2>{% if priority %}{% for c in priority[:3] %}<div style="border-top:1px solid var(--line);padding:14px 0"><span class="pill {{ c.severity|lower }}">{{ c.severity }}</span> <span class="pill {{ c.status|lower }}">{{ c.status }}</span><div class="case-title"><a href="{{ c.url }}">{{ c.title }}</a></div><div class="muted small">{{ c.source }} · {{ c.disposition or 'Pending disposition' }}</div></div>{% endfor %}{% else %}<p>No open investigations in the recorded case set.</p>{% endif %}<a class="action" href="/investigations?status=open">Open triage queue →</a></section>
<section class="card"><h2>Severity distribution</h2>{% for name,n in severity %}<div class="barrow"><span class="small">{{ name }}</span><div class="bar"><span style="width:{{ 100*n/max_count }}%"></span></div><b>{{ n }}</b></div>{% endfor %}<p class="small">Counts include closed and open cases.</p></section></div>
<div class="grid2 equal"><section class="card"><h2>Recent investigations</h2><div class="tablewrap"><table><thead><tr><th>Investigation</th><th>Severity</th><th>Status</th></tr></thead><tbody>{% for c in recent %}<tr><td><a href="{{ c.url }}">{{ c.title }}</a><div class="muted small">{{ display_time(c.time) }}</div></td><td><span class="pill {{ c.severity|lower }}">{{ c.severity }}</span></td><td><span class="pill {{ c.status|lower }}">{{ c.status }}</span></td></tr>{% endfor %}</tbody></table></div></section><section class="card"><h2>Evidence availability</h2>{% for h in health %}<div class="health"><div><b>{{ h.name }}</b><div class="muted small">{{ h.detail }}</div></div><span class="small {{ 'ok' if h.ok else 'bad' }}">{{ 'READABLE' if h.ok else 'UNAVAILABLE' }}</span></div>{% endfor %}<p class="small">These indicators check evidence accessibility, not ingestion freshness or sensor uptime.</p><div style="border-top:1px solid var(--line);padding-top:17px"><h2>Detector validation</h2>{% if quality %}<b>{{ quality.summary.true_positives + quality.summary.true_negatives }}/{{ quality.scenarios|length }}</b> scenarios passed against expected outcomes.<p class="small">{{ quality.summary.false_positives }} false positives · {{ quality.summary.false_negatives }} false negatives in this test set.</p><a href="/quality">Review validation results →</a>{% else %}<p>Validation evidence unavailable.</p>{% endif %}</div></section></div>'''

QUEUE = '''<div class="head"><div><div class="eyebrow">Analyst workflow</div><h1>Investigation queue</h1><p>Suricata, SSH, endpoint, and simulated capstone investigations in one place.</p></div><span class="pill">{{ filtered|length }} of {{ total }} cases</span></div><div class="metrics"><div class="card metric"><div class="label">Total</div><div class="num">{{ total }}</div></div><div class="card metric"><div class="label">Open / escalated</div><div class="num" style="color:var(--amber)">{{ open_count }}</div></div><div class="card metric"><div class="label">Closed</div><div class="num">{{ closed }}</div></div><div class="card metric"><div class="label">Matching filters</div><div class="num">{{ filtered|length }}</div></div></div>
<section class="card"><form class="filters" method="get" action="/investigations"><input aria-label="Search investigations" type="search" name="q" value="{{ q }}" placeholder="Search case title, source, disposition..."><select aria-label="Filter by status" name="status"><option value="all" {{ 'selected' if status=='all' else '' }}>All statuses</option><option value="open" {{ 'selected' if status=='open' else '' }}>Action required</option><option value="Closed" {{ 'selected' if status=='Closed' else '' }}>Closed</option><option value="Escalated" {{ 'selected' if status=='Escalated' else '' }}>Escalated</option><option value="New" {{ 'selected' if status=='New' else '' }}>New</option><option value="Investigating" {{ 'selected' if status=='Investigating' else '' }}>Investigating</option></select><select aria-label="Filter by severity" name="severity"><option value="all">All severities</option>{% for s in severities %}<option value="{{ s }}" {{ 'selected' if severity==s else '' }}>{{ s }}</option>{% endfor %}</select><button type="submit">Apply filters</button><a href="/investigations" style="align-self:center">Reset</a></form><div class="tablewrap"><table><thead><tr><th>Investigation</th><th>Source</th><th>Severity</th><th>Status</th><th>Disposition</th><th>Event time</th></tr></thead><tbody>{% for c in filtered %}<tr><td><a class="strong" href="{{ c.url }}">{{ c.title }}</a></td><td>{{ c.source }}</td><td><span class="pill {{ c.severity|lower }}">{{ c.severity }}</span></td><td><span class="pill {{ c.status|lower }}">{{ c.status }}</span></td><td>{{ c.disposition or '—' }}</td><td class="muted">{{ display_time(c.time) }}</td></tr>{% else %}<tr><td colspan="6">No investigations match these filters.</td></tr>{% endfor %}</tbody></table></div></section>'''

QUALITY_VIEW = '''<div class="eyebrow">Detection engineering</div><h1>Validation & quality</h1><p>Lab 12 detector validation on a defined, simulated test set. These are not production accuracy estimates.</p>{% if quality %}<div class="metrics"><div class="card metric"><div class="label">Scenarios</div><div class="num">{{ quality.scenarios|length }}</div></div><div class="card metric"><div class="label">True positives</div><div class="num">{{ s.true_positives }}</div></div><div class="card metric"><div class="label">True negatives</div><div class="num">{{ s.true_negatives }}</div></div><div class="card metric"><div class="label">False positives / negatives</div><div class="num">{{ s.false_positives }} / {{ s.false_negatives }}</div></div></div><section class="card"><h2>Scenario outcomes</h2><div class="tablewrap"><table><thead><tr><th>Scenario</th><th>Expected detection</th><th>Observed detection</th><th>Outcome</th></tr></thead><tbody>{% for t in quality.scenarios %}<tr><td>{{ t.scenario }}</td><td>{{ 'Yes' if t.expected_detection else 'No' }}</td><td>{{ 'Yes' if t.actual_detection else 'No' }}</td><td><span class="pill {{ 'closed' if t.outcome in ['TP','TN'] else 'high' }}">{{ t.outcome }}</span></td></tr>{% endfor %}</tbody></table></div></section><p class="small">Precision and recall reflect only these ten controlled scenarios; they do not establish real-world detector performance.</p>{% else %}<section class="card"><h2>Evidence not available</h2><p>Expected file: ~/SOC-Lab-12/evidence/detection-quality.json</p></section>{% endif %}'''

CAPSTONE_VIEW = '''<div class="eyebrow"><a href="/investigations">← Investigation queue</a> / Simulated incident</div><div class="head"><div><h1>{{ c.id }}</h1><div class="case-title">{{ c.title }}</div><p>Authorized training simulation · Evidence-driven incident assessment</p></div><div><span class="pill high">High · provisional</span> <span class="pill escalated">Escalated</span></div></div><div class="metrics"><div class="card"><div class="muted small">Assessment</div><b>{{ d.classification }}</b></div><div class="card"><div class="muted small">Confidence</div><b>{{ d.confidence }}</b></div><div class="card"><div class="muted small">Compromise confirmed</div><b class="bad">{{ 'Yes' if d.confirmed_compromise else 'No' }}</b></div><div class="card"><div class="muted small">Script execution confirmed</div><b class="bad">{{ 'Yes' if d.confirmed_script_execution else 'No' }}</b></div></div><div class="grid2"><section class="card"><h2>Unified evidence timeline · {{ c.timeline|length }} events</h2><div class="timeline">{% for e in events %}<div class="event"><div class="time">{{ display_time(e.timestamp) }} · {{ e.source|upper }}</div><div class="desc">{{ e.description }}</div></div>{% endfor %}</div></section><section><div class="card callout"><h2>Analyst decision</h2><p><b>Escalation:</b> {{ d.escalation }}</p><p><b>Disposition:</b> Compromise unconfirmed</p><p><b>Credential response:</b> {{ d.credential_action }}</p><p><b>Host isolation:</b> {{ d.host_isolation }}</p><p><b>Exfiltration confirmed:</b> {{ 'Yes' if d.confirmed_exfiltration else 'No' }}</p><p class="small">Exercise complete does not mean compromise or containment is confirmed.</p></div><div class="card" style="margin-top:16px"><h2>Investigation report</h2><div class="report">{{ report }}</div></div></section></div>'''

def display_time(value):
    if not value:
        return 'Unknown'
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if dt.tzinfo is None:
            return dt.strftime('%d %b %Y · %H:%M') + ' (timezone unspecified)'
        return dt.strftime('%d %b %Y · %H:%M %Z').strip()
    except (ValueError, TypeError, OverflowError):
        return str(value)

def stamp(value):
    try:
        d = datetime.fromisoformat(str(value).replace('Z','+00:00'))
        if d.tzinfo is None:
            # Source timezone not established: do not pretend UTC precision.
            return (0, str(value))
        return (1, d.astimezone(timezone.utc).timestamp())
    except (ValueError, TypeError, OverflowError):
        return (-1, 0)

def get_cases():
    cases, health = collect_cases()
    for h in health:
        h['detail'] = 'Local evidence source'
        if h['name'] == 'Capstone Investigation':
            h['ok'] = bool(load_capstone())
            h['detail'] = 'JSON evidence and decision'
    return cases, health

def counts(cases):
    closed = sum(str(c['status']).lower() == 'closed' for c in cases)
    return closed, len(cases)-closed

def priority_key(c):
    rank = {'Critical':0,'High':1,'Medium':2,'Low':3,'Unknown':4}
    return (rank.get(c['severity'],4), -stamp(c['time'])[1] if stamp(c['time'])[0]==1 else 0)

def quality_data():
    try:
        value = json.loads(QUALITY.read_text())
        if isinstance(value.get('summary'),dict) and isinstance(value.get('scenarios'),list):
            return value
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return None

def page(title, active, template, **kwargs):
    kwargs.setdefault("display_time", display_time)
    body = render_template_string(template, **kwargs)
    return render_template_string(BASE, title=title, active=active, body=body)

def overview():
    cases, health = get_cases()
    closed, opened = counts(cases)
    severity = [(s, sum(c['severity']==s for c in cases)) for s in ('Critical','High','Medium','Low','Unknown')]
    priority = sorted((c for c in cases if c['status'].lower()!='closed'), key=priority_key)
    recent = sorted(cases, key=lambda c:stamp(c['time']), reverse=True)[:5]
    return page('Command center','overview',OVERVIEW,total=len(cases),closed=closed,open_count=opened,high=sum(c['severity'] in ('Critical','High') for c in cases),priority=priority,recent=recent,severity=severity,max_count=max(1,*(n for _,n in severity)),health=health,quality=quality_data())

def investigations():
    cases, _ = get_cases()
    closed, opened = counts(cases)
    q = request.args.get('q','').strip()[:160]
    status = request.args.get('status','all')
    severity = request.args.get('severity','all')
    if status not in ('all','open','Closed','Escalated','New','Investigating'): status='all'
    if severity not in ('all','Critical','High','Medium','Low','Unknown'): severity='all'
    filtered=[]
    for c in cases:
        if q and q.casefold() not in ' '.join(str(c.get(k,'')) for k in ('title','source','disposition','url')).casefold():continue
        if status=='open' and c['status'].lower()=='closed':continue
        if status not in ('all','open') and c['status'].lower()!=status.lower():continue
        if severity!='all' and c['severity']!=severity:continue
        filtered.append(c)
    filtered.sort(key=lambda c:(c['status'].lower()=='closed',priority_key(c)))
    return page('Investigations','investigations',QUEUE,total=len(cases),closed=closed,open_count=opened,filtered=filtered,q=q,status=status,severity=severity,severities=('Critical','High','Medium','Low','Unknown'))

def quality():
    data=quality_data()
    return page('Detection quality','quality',QUALITY_VIEW,quality=data,s=data['summary'] if data else {})

def capstone():
    c=load_capstone()
    if c is None:
        from flask import abort
        abort(404)
    path=HOME/'SOC-Capstone/reports/capstone-investigation.md'
    report=path.read_text(encoding='utf-8') if path.is_file() else 'Report unavailable.'
    events=sorted(c['timeline'],key=lambda e:stamp(e.get('timestamp','')))
    return page(c['id'],'investigations',CAPSTONE_VIEW,c=c,d=c['decision'],events=events,report=report)
