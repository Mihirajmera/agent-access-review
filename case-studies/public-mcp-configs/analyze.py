"""Run agent-access-review over the collected configs and print aggregate numbers only.
Usage: python analyze.py   (run with the agent-access-review venv, from the repo checkout)"""
import json
import shutil
import sys
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path

from agent_access_review.checks import run_all
from agent_access_review.parsers import load

HERE = Path(__file__).parent
# Checks a bare config file can answer. Owner, approval and rotation dates need a manifest.
CONFIG_CHECKS = ['AAR-04', 'AAR-05', 'AAR-06', 'AAR-09', 'AAR-10', 'AAR-11', 'AAR-13', 'AAR-14']
NAMES = {'claude_desktop': 'claude_desktop_config.json', 'claude_code': '.mcp.json',
         'vscode': 'mcp.json', 'cursor': 'mcp.json'}


def main() -> None:
    rows = [json.loads(l) for l in (HERE / 'index.jsonl').open(encoding='utf-8')]
    # One config per unique content: forks and templates copied verbatim count once.
    first = {}
    for r in rows:
        first.setdefault(r['sha'], r)
    per_check, per_kind, packages, malware, vulnerable, deprecated = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    servers_total = unpinned_servers = pkg_servers = 0
    parsed = skipped = empty = 0
    kind_check, kind_pkg, kind_unpinned = Counter(), Counter(), Counter()
    tmp = Path(tempfile.mkdtemp())
    for sha, r in first.items():
        src = HERE / 'files' / f'{sha}.json'
        d = tmp / sha
        d.mkdir()
        dst = d / NAMES[r['kind']]
        shutil.copy(src, dst)
        try:
            agents = load(dst)
        except Exception:
            skipped += 1
            continue
        if not agents or not any(a.grants for a in agents):
            empty += 1
            continue
        parsed += 1
        per_kind[r['kind']] += 1
        failed = set()
        for a in agents:
            for g in a.grants:
                servers_total += 1
                if g.package and g.pinned is not None:
                    pkg_servers += 1
                    unpinned_servers += g.pinned is False
                    packages[f'{g.ecosystem or "docker"}:{g.package}'] += 1
            for f in run_all(a, date(2026, 11, 11)):
                if f.check_id in CONFIG_CHECKS:
                    failed.add(f.check_id)
                if f.check_id == 'AAR-14':
                    (malware if 'malicious' in f.message else vulnerable)[f.message.split(' runs ')[1].split(',')[0]] += 1
                if f.check_id == 'AAR-13':
                    deprecated[f.message.split(' runs ')[1].split(',')[0]] += 1
        per_check.update(failed)
        kind_check.update((r['kind'], c) for c in failed)
        for a in agents:
            for g in a.grants:
                if g.package and g.pinned is not None:
                    kind_pkg[r['kind']] += 1
                    kind_unpinned[r['kind']] += g.pinned is False
    shutil.rmtree(tmp, ignore_errors=True)
    print('by client (configs | unpinned servers | AAR-06 | AAR-10 | AAR-13 | AAR-14):')
    for k, n in per_kind.items():
        print(f'  {k:15s} {n:5d} | {kind_unpinned[k] / max(kind_pkg[k], 1):4.0%} of {kind_pkg[k]:4d} | '
              + ' | '.join(f'{kind_check[(k, c)] / n:5.1%}' for c in ['AAR-06', 'AAR-10', 'AAR-13', 'AAR-14']))
    print(f'search hits: {len(rows)}  unique configs: {len(first)}  reviewed: {parsed}  '
          f'no servers: {empty}  unreadable: {skipped}')
    print('by client:', dict(per_kind))
    print(f'servers: {servers_total}  registry/image servers: {pkg_servers}  unpinned: {unpinned_servers} '
          f'({unpinned_servers / max(pkg_servers, 1):.0%})')
    print('\nconfigs failing each check:')
    for c in CONFIG_CHECKS:
        print(f'  {c}: {per_check[c]:5d}  {per_check[c] / max(parsed, 1):.1%}')
    print('\ntop packages:', packages.most_common(25))
    print('\ndeprecated servers (config count):', deprecated.most_common(15))
    print('\nknown-vulnerable versions:', vulnerable.most_common(15))
    print('\nmalicious packages:', malware.most_common(10))


if __name__ == '__main__':
    sys.exit(main())
