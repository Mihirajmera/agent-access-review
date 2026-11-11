"""Build the wheel without pip and check it ships everything the CLI needs at runtime:
the capability and control catalogs, the bundled examples, and the console script."""
import sys
import zipfile
from pathlib import Path

from setuptools import build_meta

dist = Path('dist')
dist.mkdir(exist_ok=True)
wheel = dist / build_meta.build_wheel(str(dist))
names = set(zipfile.ZipFile(wheel).namelist())
required = {
    'agent_access_review/catalog.yaml',
    'agent_access_review/controls.yaml',
    'agent_access_review/advisories.yaml',
    'agent_access_review/examples/agents.yaml',
    'agent_access_review/examples/claude_desktop_config.json',
    'agent_access_review/examples/vscode-mcp.json',
}
missing = sorted(required - names)
entry_points = next((n for n in names if n.endswith('.dist-info/entry_points.txt')), None)
script_ok = entry_points and 'agent-access-review = agent_access_review.__main__:main' in \
    zipfile.ZipFile(wheel).read(entry_points).decode()
print(f'{wheel.name}: {len(names)} files')
if missing or not script_ok:
    sys.exit(f'missing from wheel: {missing or ""} {"" if script_ok else "console script"}')
print('wheel contains the catalogs, examples and console script')
