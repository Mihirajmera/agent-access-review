"""Turn agent configuration files into the normalized inventory model.

Two input formats are supported:

* MCP configs (Claude Desktop, Cursor, VS Code `.vscode/mcp.json`, ...). These carry no
  ownership or approval data, which is exactly what makes them "shadow agents".
* Agent manifests (`agents.yaml`), a governed format for LangChain / CrewAI / custom agents
  that records owner, approval, tools, credentials and usage.

Secrets are redacted here, before anything reaches the evidence store.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .model import Agent, Credential, Grant

CATALOG = yaml.safe_load((Path(__file__).parent / 'catalog.yaml').read_text(encoding='utf-8'))
# Look servers up by package name or any alias (official Docker image, uvx name, ...).
SERVERS = {alias: profile for name, profile in CATALOG['servers'].items()
           for alias in [name, *profile.get('aliases', [])]}

REDACTED = '***REDACTED***'
SECRET_NAME = re.compile(r'TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|(^|_)PAT($|_)|AUTH', re.I)
SECRET_FLAG = re.compile(r'^(--?[\w-]*(?:token|secret|password|api-?key)[\w-]*)=(.+)$', re.I)
# The same flag on its own, with the secret in the next argument (`--token value`). Most CLIs
# document this form, so a parser that only understands `--token=value` misses the common case.
SECRET_FLAG_NAME = re.compile(r'^--?[\w-]*(?:token|secret|password|api-?key)[\w-]*$', re.I)
DSN_PASSWORD = re.compile(r'^([a-z][a-z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)', re.I)
# docker flags that consume the next argument, so it is not mistaken for the image name
DOCKER_VALUE_FLAGS = {'-e', '--env', '-v', '--volume', '--name', '--network', '-p', '--publish',
                      '--mount', '--env-file', '-w', '--workdir', '-u', '--user', '--entrypoint'}


def is_reference(value: str) -> bool:
    """True when a secret field points at a secret store or env var instead of holding the secret."""
    v = str(value).strip()
    return (v == '' or '${' in v or v.startswith(('$', 'op://', 'vault:', 'secretsmanager:', 'env:', '{{'))
            or (v.startswith('<') and v.endswith('>')))


def secret_args(args: list[str]) -> list[tuple[int, str, str]]:
    """Every hardcoded secret passed on a command line, as (index of the value, flag name, value).

    Both spellings count: `--token=value` and `--token value`. The separated form is what most
    CLIs document, and missing it meant the secret was neither reported as a credential nor
    masked, so it reached the evidence file verbatim.
    """
    found = []
    for i, arg in enumerate(args):
        if (m := SECRET_FLAG.match(arg)) and not is_reference(m.group(2)):
            found.append((i, m.group(1).lstrip('-'), m.group(2)))
        elif SECRET_FLAG_NAME.match(arg) and i + 1 < len(args):
            value = args[i + 1]
            # A following flag means the value is missing, not that it is empty.
            if not is_reference(value) and not value.startswith('-'):
                found.append((i + 1, arg.lstrip('-'), value))
    return found


class ConfigError(ValueError):
    """A file in a supported format whose structure isn't what the format requires."""


def load(path: Path, source: str | None = None) -> list[Agent]:
    """Parse one file. Returns [] for files that are neither format. `source` is the path recorded
    in the inventory and evidence (defaults to the path as given). Raises ValueError (including
    ConfigError) or yaml.YAMLError for malformed input, never anything else."""
    try:
        return _load(path, source or path.as_posix())
    except (AttributeError, KeyError, TypeError, RecursionError) as e:
        # Wrong shapes (a list where an object belongs, a missing id, ...) and absurd nesting
        # are input problems, not crashes: report them like any other malformed file.
        raise ConfigError(f'unexpected structure ({type(e).__name__}: {e})') from e


def _jsonc(text: str) -> str:
    """Remove comments and trailing commas, leaving JSON string contents untouched."""
    string = r'"(?:\\.|[^"\\])*"'
    text = re.sub(string + r'|//[^\r\n]*|/\*.*?\*/',
                  lambda m: m[0] if m[0].startswith('"') else re.sub(r'[^\r\n]', ' ', m[0]),
                  text, flags=re.DOTALL)
    return re.sub(string + r'|,\s*(?=[}\]])',
                  lambda m: m[0] if m[0].startswith('"') else m[0][1:], text)


def _load(path: Path, source: str) -> list[Agent]:
    # utf-8-sig reads a plain UTF-8 file exactly like utf-8 and also drops a leading byte-order
    # mark. Editors on Windows (Notepad, PowerShell's Out-File) write one by default, and a BOM
    # made json.loads fail, which discover() then reported as a skipped file: the agent vanished
    # from the review without anyone being told why.
    text = path.read_text(encoding='utf-8-sig')
    if path.suffix.lower() == '.json':
        data = json.loads(_jsonc(text))
        servers = data.get('mcpServers', data.get('servers')) if isinstance(data, dict) else None
        if isinstance(servers, dict):
            return [parse_mcp_config(path, data, servers, source)]
    elif path.suffix.lower() in {'.yaml', '.yml'}:
        data = yaml.safe_load(text) or {}
        if isinstance(data, dict) and isinstance(data.get('agents'), list):
            return parse_manifest(path, data, source)
    return []


SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', '.tox'}


def discover(paths: list[Path]) -> list[Agent]:
    agents: list[Agent] = []
    for p in paths:
        files = sorted(f for f in p.rglob('*') if f.is_file() and not SKIP_DIRS & set(f.parts)) \
            if p.is_dir() else [p]
        for f in files:
            if f.suffix.lower() not in {'.json', '.yaml', '.yml'}:
                continue
            # Inside a scanned folder, record "<folder>/<relative path>" so evidence (and its hash)
            # doesn't depend on where the folder sits on this machine.
            source = f'{p.name}/{f.relative_to(p).as_posix()}' if p.is_dir() else None
            try:
                agents.extend(load(f, source))
            except (ValueError, yaml.YAMLError) as e:
                # Malformed configs and unrelated files land here; skip, don't abort the review
                print(f'warning: skipped {f}: {type(e).__name__}: {e}', file=sys.stderr)
    return _unique_ids(agents)


def _unique_ids(agents: list[Agent]) -> list[Agent]:
    """Give every agent an id no other agent in this run shares.

    The id used to come from the file name alone, so two hosts configured in different folders
    both produced `claude-desktop-config`: evidence/<id>.json was written twice and the second
    silently replaced the first, and the OSCAL results kept only one of the two observations.
    Ids that occur once keep their existing value; colliding ones fall back to their source path,
    which is already relative to the scanned folder.
    """
    counts = Counter(agent.id for agent in agents)
    taken: set[str] = set()
    for agent in agents:
        candidate = agent.id
        if counts[candidate] > 1:
            parts = [p for p in str(agent.source).replace('\\', '/').split('/') if p]
            if parts:
                parts[-1] = Path(parts[-1]).stem
            stem = _slug('-'.join(parts)) or candidate
            candidate, n = stem, 2
            while candidate in taken:
                candidate, n = f'{stem}-{n}', n + 1
        while candidate in taken:
            candidate = f'{candidate}-2'
        taken.add(candidate)
        agent.id = candidate
    return agents


# --------------------------------------------------------------------------- MCP configs

def parse_mcp_config(path: Path, data: dict, servers: dict, source: str | None = None) -> Agent:
    agent = Agent(id=_slug(path.stem if path.stem not in {'mcp', 'config'} else f'{path.parent.name}-{path.stem}'),
                  name=f'MCP host ({path.name})', source=source or path.as_posix(),
                  source_type='mcp-config')
    raw = copy.deepcopy(data)
    raw_servers = raw.get('mcpServers', raw.get('servers'))
    for name, spec in servers.items():
        grant, creds = _mcp_server(name, spec)
        agent.grants.append(grant)
        agent.credentials.extend(creds)
        _redact_server(raw_servers[name])
    agent.raw = raw
    return agent


def _mcp_server(name: str, spec: dict) -> tuple[Grant, list[Credential]]:
    creds = []
    for key, value in (spec.get('env') or {}).items():
        if SECRET_NAME.search(key):
            creds.append(Credential(name=f'{name}.{key}', hardcoded=not is_reference(value)))
    for key, value in (spec.get('headers') or {}).items():
        if key.lower() in {'authorization', 'x-api-key', 'api-key'} or SECRET_NAME.search(key):
            token = str(value).split(' ', 1)[-1]      # strip "Bearer "
            creds.append(Credential(name=f'{name}.header.{key}', hardcoded=not is_reference(token)))

    url = spec.get('url')
    if url:                                           # remote server
        host = urlparse(url).hostname or ''
        profile = CATALOG['remote_hosts'].get(host)
        grant = _grant_from_profile(name, profile, resource=url, args=[])
        grant.endpoint = url
        return grant, creds

    raw_args = [str(a) for a in spec.get('args', [])]
    package, pinned, args = _package(spec.get('command', ''), raw_args)
    # Credentials are looked for in the command line as written: _package() drops the flags
    # (--token and friends) to get at the server's own arguments, so scanning its result would
    # only ever see the bare value.
    for a in raw_args:
        if (m := DSN_PASSWORD.match(a)) and not is_reference(m.group(2)):
            creds.append(Credential(name=f'{name}.connection-string', hardcoded=True))
    for _, flag, _ in secret_args(raw_args):
        creds.append(Credential(name=f'{name}.arg.{flag}', hardcoded=True))
    profile = SERVERS.get(package) if package else None
    resource = package if pinned is not None else ' '.join([spec.get('command', name), *redact_args(raw_args)]).strip()
    grant = _grant_from_profile(name, profile, resource=resource, args=args)
    grant.package, grant.pinned = package, pinned
    mounts = _docker_mounts(spec.get('command', ''), [str(a) for a in spec.get('args', [])])
    if mounts and grant.known:
        # In a container the server only reaches what's mounted from the host, so the host
        # paths are what the agent can really touch (and what least privilege is judged on).
        grant.scopes = [src for src, _ in mounts]
        if profile.get('resource_from') == 'paths':
            grant.resource = ', '.join(src + (' (read-only)' if ro else '') for src, ro in mounts)
            if all(ro for _, ro in mounts):
                grant.actions &= {'read'}
    return grant, creds


def _docker_mounts(command: str, args: list[str]) -> list[tuple[str, bool]]:
    """Host paths bind-mounted into a docker/podman container, as (host path, read-only).
    Named volumes aren't host paths and are ignored."""
    if Path(command).name.lower().removesuffix('.exe') not in {'docker', 'podman'}:
        return []
    mounts = []
    for flag, value in zip(args, args[1:]):
        if flag in ('-v', '--volume'):
            drive = value[:2] if re.match(r'^[A-Za-z]:[\\/]', value) else ''
            parts = value[len(drive):].split(':')
            src, opts = drive + parts[0], parts[2] if len(parts) > 2 else ''
            ro = 'ro' in opts.split(',')
        elif flag == '--mount':
            fields = dict(f.split('=', 1) if '=' in f else (f, 'true') for f in value.split(','))
            src = fields.get('src') or fields.get('source') or ''
            ro = fields.get('ro') == 'true' or fields.get('readonly') == 'true' or 'ro' in fields
        else:
            continue
        if re.match(r'^([/~.]|[A-Za-z]:[\\/])', src):
            mounts.append((src, ro))
    return mounts


def _package(command: str, args: list[str]) -> tuple[str | None, bool | None, list[str]]:
    """Return (package name without version, pinned?, remaining server args)."""
    cmd = Path(command).name.lower().removesuffix('.cmd').removesuffix('.exe')
    if cmd in {'npx', 'bunx', 'pnpx'}:
        rest = [a for a in args if not a.startswith('-')]
        if not rest:
            return None, None, []
        spec = rest[0]
        at = spec.rfind('@')
        if at > 0:                                    # "@scope/name@1.2.3" or "name@1.2.3"
            name, version = spec[:at], spec[at + 1:]
            return name, _is_exact(version), rest[1:]
        return spec, False, rest[1:]
    if cmd == 'uvx':
        if '--from' in args:
            spec = args[args.index('--from') + 1]
            rest = [a for a in args[args.index('--from') + 2:] if not a.startswith('-')][1:]
        else:
            rest = [a for a in args if not a.startswith('-')]
            spec, rest = (rest[0], rest[1:]) if rest else (None, [])
        if spec is None:
            return None, None, []
        for sep in ('==', '@'):
            if sep in spec:
                name, version = spec.split(sep, 1)
                return name, _is_exact(version), rest
        return spec, False, rest
    if cmd in {'docker', 'podman'} and 'run' in args:
        tokens = args[args.index('run') + 1:]
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in DOCKER_VALUE_FLAGS:
                i += 2
                continue
            if t.startswith('-'):
                i += 1
                continue
            image, rest = t, tokens[i + 1:]
            if '@sha256:' in image:                   # only a digest is immutable
                return image.split('@', 1)[0], True, rest
            last = image.rsplit('/', 1)[-1]
            return (image.rsplit(':', 1)[0] if ':' in last else image), False, rest
        return None, None, []
    # A binary or script on disk (python server.py, node index.js, an installed CLI).
    # It may be in the catalog by name, but there is no package version to assess.
    return (cmd or None), None, args


def _is_exact(version: str) -> bool:
    return bool(re.fullmatch(r'v?\d+(\.\d+){1,3}([-+.][0-9A-Za-z.]+)?', version))


def _grant_from_profile(name: str, profile: dict | None, resource: str, args: list[str]) -> Grant:
    if profile is None:
        return Grant(tool=name, resource=resource, actions={'unknown'}, known=False)
    if profile.get('resource_from') == 'paths':
        resource = ', '.join(a for a in args if not a.startswith('-')) or resource
    elif profile.get('resource_from') == 'dsn':
        resource = next((redact_arg(a) for a in args if '://' in a), resource)
    return Grant(
        tool=name,
        category=profile['tool'],
        resource=resource,
        actions=set(profile['actions']),
        scopes=[a for a in args if not a.startswith('-')] if profile.get('resource_from') == 'paths' else [],
        data_classification=profile.get('data_classification', 'internal'),
        untrusted_input=profile.get('untrusted_input', False),
        egress=profile.get('egress', False),
    )


def _redact_server(spec: dict) -> None:
    for block in ('env', 'headers'):
        for key, value in (spec.get(block) or {}).items():
            token = str(value).split(' ', 1)[-1]
            if (SECRET_NAME.search(key) or key.lower() in {'authorization', 'x-api-key', 'api-key'}) \
                    and not is_reference(token):
                spec[block][key] = REDACTED
    if 'args' in spec:
        spec['args'] = redact_args([str(a) for a in spec['args']])


def redact_args(args: list[str]) -> list[str]:
    """Mask every hardcoded secret in a command line, keeping the flag readable."""
    masked = [redact_arg(a) for a in args]
    for i, _, value in secret_args(args):
        if masked[i] == value:          # a bare value: "--token value" rather than "--token=value"
            masked[i] = REDACTED
    return masked


def redact_arg(arg: str) -> str:
    """Mask a password in a connection string or the value of a --token=... style flag."""
    if (m := DSN_PASSWORD.match(arg)) and not is_reference(m.group(2)):
        return f'{m.group(1)}{REDACTED}{m.group(3)}{arg[m.end():]}'
    if (m := SECRET_FLAG.match(arg)) and not is_reference(m.group(2)):
        return f'{m.group(1)}={REDACTED}'
    return arg


# --------------------------------------------------------------------------- manifests

def parse_manifest(path: Path, data: dict, source: str | None = None) -> list[Agent]:
    agents = []
    for rec in data['agents']:
        agent = Agent(
            id=_slug(rec['id']),
            name=rec.get('name', rec['id']),
            source=source or path.as_posix(),
            source_type='agent-manifest',
            owner=rec.get('owner'),
            approved_by=rec.get('approved_by'),
            approved_on=_date(rec.get('approved_on')),
            raw=copy.deepcopy(rec),
        )
        for t in rec.get('tools', []):
            agent.grants.append(Grant(
                tool=t['name'],
                resource=t.get('resource', t['name']),
                actions=set(t.get('actions', ['read'])),
                scopes=list(t.get('scopes', [])),
                data_classification=t.get('data_classification', 'internal'),
                untrusted_input=bool(t.get('untrusted_input', False)),
                egress=bool(t.get('egress', False)),
                requires_approval=bool(t.get('requires_approval', False)),
                sandboxed=bool(t.get('sandboxed', False)),
                last_used=_date(t.get('last_used')),
                package=t.get('package'),
                pinned=t.get('pinned'),
                endpoint=t.get('endpoint'),
                category=t.get('type'),
            ))
        for c in rec.get('credentials', []):
            agent.credentials.append(Credential(
                name=f"{c['tool']}.{c['name']}" if c.get('tool') else c['name'],
                hardcoded=c.get('source') == 'hardcoded',
                last_rotated=_date(c.get('last_rotated')),
            ))
        agents.append(agent)
    return agents


def _date(value) -> date | None:
    if value in (None, ''):
        return None
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def _slug(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
