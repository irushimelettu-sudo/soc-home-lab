from pathlib import Path
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'dashboard'))
import app as dashboard
client=dashboard.app.test_client()
for route in ('/','/investigations','/quality','/alerts','/detections','/capstone/CAPSTONE-001'):
    result=client.get(route)
    print(('[PASS]' if result.status_code==200 else '[FAIL]'),route,result.status_code)
    assert result.status_code==200
assert len(dashboard.enrich_alerts())==3
print('[PASS] 3 synthetic Suricata alerts')
print('[COMPLETE] Standalone smoke test passed')
