"""Collect public MCP client configs from GitHub code search (max 1000 per query).
Writes files/<sha256>.json (deduplicated by content) and index.jsonl (kind, repo, path, sha).
Resumable: files already indexed are skipped. Data stays local; only aggregates are published."""
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OUT = Path(__file__).parent
FILES = OUT / 'files'
FILES.mkdir(exist_ok=True)
QUERIES = {
    'claude_desktop': 'filename:claude_desktop_config.json mcpServers',
    'claude_code': 'filename:.mcp.json mcpServers',
    'vscode': 'path:.vscode filename:mcp.json servers',
    'cursor': 'path:.cursor filename:mcp.json mcpServers',
}


def search(q: str, page: int) -> list[dict]:
    for _ in range(8):
        r = subprocess.run(['gh', 'api', '-X', 'GET', 'search/code', '-f', f'q={q}', '-f', 'per_page=100',
                            '-f', f'page={page}'], capture_output=True, text=True, encoding='utf-8')
        if r.returncode == 0:
            return json.loads(r.stdout).get('items', [])
        print('search retry', q, page, r.stderr[:120], file=sys.stderr, flush=True)
        time.sleep(65 if 'rate limit' in (r.stdout + r.stderr).lower() else 20)
    return []


def fetch(it: dict) -> bytes | None:
    ref = it['url'].split('ref=')[-1]                  # the commit the match was indexed at
    raw = (f"https://raw.githubusercontent.com/{it['repository']['full_name']}/{ref}/"
           f"{urllib.parse.quote(it['path'])}")
    for _ in range(3):
        try:
            with urllib.request.urlopen(raw, timeout=20) as resp:
                return resp.read(512_000)
        except Exception:
            time.sleep(2)
    return None


def main() -> None:
    index = OUT / 'index.jsonl'
    done = set()
    if index.exists():
        for line in index.open(encoding='utf-8'):
            r = json.loads(line)
            done.add((r['repo'], r['path']))
    with index.open('a', encoding='utf-8') as idx:
        for kind, q in QUERIES.items():
            for page in range(1, 11):
                items = search(q, page)
                todo = [it for it in items if (it['repository']['full_name'], it['path']) not in done]
                with ThreadPoolExecutor(16) as pool:
                    bodies = list(pool.map(fetch, todo))
                for it, body in zip(todo, bodies):
                    if body is None:
                        continue
                    repo, path = it['repository']['full_name'], it['path']
                    sha = hashlib.sha256(body).hexdigest()
                    (FILES / f'{sha}.json').write_bytes(body)
                    idx.write(json.dumps({'kind': kind, 'repo': repo, 'path': path, 'sha': sha}) + '\n')
                    done.add((repo, path))
                idx.flush()
                print(kind, page, len(items), 'new', len(todo), flush=True)
                if len(items) < 100:
                    break
                time.sleep(7)                     # code search allows about 10 requests a minute


if __name__ == '__main__':
    main()
