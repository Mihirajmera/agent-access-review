"""Classify credential-looking values in the collected configs. Prints counts only, never values."""
import json
import re
import sys
from collections import Counter
from pathlib import Path

from agent_access_review.parsers import SECRET_NAME, is_reference

HERE = Path(__file__).parent
PLACEHOLDER = re.compile(r'your|xxx|<|>|\.\.\.|placeholder|example|changeme|change_me|replace|insert|here|dummy|'
                         r'test|todo|redacted|\*\*\*|^sk-\.\.\.|^\s*$|token$|key$|secret$', re.I)
PROVIDER = {
    'GitHub token': r'^(ghp_|github_pat_|gho_|ghs_)[A-Za-z0-9_]{20,}$',
    'OpenAI/Anthropic key': r'^sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}$',
    'Slack token': r'^xox[abposr]-[A-Za-z0-9-]{10,}$',
    'AWS access key': r'^(AKIA|ASIA)[A-Z0-9]{16}$',
    'Google API key': r'^AIza[0-9A-Za-z_-]{30,}$',
}


def values(obj, key=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from values(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from values(v, key)
    elif isinstance(obj, str):
        yield key, obj


def main():
    first = {}
    for l in (HERE / 'index.jsonl').open(encoding='utf-8'):
        r = json.loads(l)
        first.setdefault(r['sha'], r)
    kinds, configs_real, configs_any = Counter(), set(), set()
    for sha in first:
        try:
            doc = json.loads((HERE / 'files' / f'{sha}.json').read_text(encoding='utf-8-sig'))
        except Exception:
            continue
        servers = doc.get('mcpServers') or doc.get('servers') or {}
        for spec in servers.values() if isinstance(servers, dict) else []:
            if not isinstance(spec, dict):
                continue
            for k, v in values({'env': spec.get('env'), 'headers': spec.get('headers')}):
                if not SECRET_NAME.search(k) or is_reference(v):
                    continue
                configs_any.add(sha)
                if PLACEHOLDER.search(v) or len(v) < 16:
                    kinds['placeholder or too short to be real'] += 1
                    continue
                label = next((n for n, p in PROVIDER.items() if re.match(p, v)), 'other long value')
                kinds[label] += 1
                configs_real.add(sha)
    total = len(first)
    print(f'unique configs: {total}')
    print(f'configs with any credential-named value: {len(configs_any)} ({len(configs_any) / total:.1%})')
    print(f'configs with a real-looking credential:   {len(configs_real)} ({len(configs_real) / total:.1%})')
    for k, n in kinds.most_common():
        print(f'  {k}: {n}')


if __name__ == '__main__':
    sys.exit(main())
