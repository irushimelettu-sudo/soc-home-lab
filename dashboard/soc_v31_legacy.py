"""Safe visual adapter for historical case routes. Does not touch POST handlers."""
import re
from html import unescape
from flask import request
from soc_command_v3 import page

ROUTES = {'/alerts':('Suricata triage','alerts'), '/detections':('Detection staging','detections')}

def is_legacy_path(path):
    return path in ROUTES or path.startswith('/case/') or (path.startswith('/detections/') and len(path)>len('/detections/'))

def adapt(response):
    if request.method != 'GET' or response.status_code != 200 or not is_legacy_path(request.path):
        return response
    if not response.mimetype == 'text/html':
        return response
    html = response.get_data(as_text=True)
    body = re.search(r'<body\b[^>]*>(.*?)</body\s*>',html,re.I|re.S)
    if not body:
        return response
    content = body.group(1)
    # Remove the old duplicated global navigation, leaving links and forms intact.
    content = re.sub(r'<nav\b[^>]*>.*?</nav\s*>','',content,flags=re.I|re.S)
    # Remove the old decorative SSH navigation banner (its destination is in the sidebar).
    content = re.sub(r'<!-- SOC LAB 06 NAVIGATION -->\s*<div\b[^>]*>.*?</div\s*>','',content,count=1,flags=re.I|re.S)
    title, active = ROUTES.get(request.path,('Investigation detail','investigations'))
    back = '/alerts' if request.path.startswith('/case/') else '/detections'
    heading = ('Suricata alert investigation' if request.path.startswith('/case/') else 'Detection investigation')
    intro = ('<div class="eyebrow">CASE REVIEW · HISTORICAL LAB EVIDENCE</div>'
             '<h1>'+heading+'</h1><p>Analyst case details and saved decisions.</p>') if request.path not in ROUTES else (
             '<div class="eyebrow">ANALYST WORKFLOW · HISTORICAL LAB EVIDENCE</div>')
    # Existing form names, actions, options, CSRF fields (if any), and links are preserved.
    wrapped = '<div class="legacy-content">'+intro+content+'</div>'
    response.set_data(page(title,active,'{{ content|safe }}',content=wrapped))
    response.headers.pop('Content-Length',None)
    response.headers['Cache-Control']='no-store'
    return response
