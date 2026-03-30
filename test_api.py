#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import time

time.sleep(2)

try:
    url = 'http://127.0.0.1:8000/system/chat'
    payload = json.dumps({
        'message': 'Test die neue Task-Anzeige',
        'run_script': True,
        'lookback_hours': 24,
        'history': [],
        'report_context': None
    }).encode('utf-8')
    
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=45) as response:
        data = json.loads(response.read().decode('utf-8'))
    
    print(f"✓ API responding")
    print(f"✓ Tasks generated: {len(data.get('generated_tasks', []))}")
    print(f"✓ Reply length: {len(data.get('reply', ''))}")
    
    if data.get('generated_tasks'):
        first = data['generated_tasks'][0]
        print(f"✓ First task severity: {first['severity']}")
        print(f"✓ First task host: {first['host']}")
        print(f"✓ First task title: {first['title'][:50]}")
        print(f"✓ First task has recommended_checks: {len(first.get('recommended_checks', [])) > 0}")
    
    print("\n✓✓✓ All tests passed! ✓✓✓")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
