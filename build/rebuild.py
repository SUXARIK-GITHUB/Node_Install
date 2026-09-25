#!/usr/bin/env python3
from pathlib import Path
import subprocess
b=Path(__file__).resolve().parent
s=(b/'installer.template.sh').read_text(encoding='utf-8')
s=s.replace('@@PYTHON_HELPER@@',(b/'node_helper.py').read_text(encoding='utf-8').rstrip())
s=s.replace('@@COLLECT_INPUT@@',(b/'collect-input.sh').read_text(encoding='utf-8').rstrip())
s=s.replace('@@HEALTH_SCRIPT@@',(b/'health.sh').read_text(encoding='utf-8').rstrip())
if '@@' in s: raise SystemExit('Unresolved placeholder')
p=b.parent/'install.sh'
p.write_text(s,encoding='utf-8');p.chmod(0o755)
subprocess.run(['bash','-n',str(p)],check=True)
print(str(p))
