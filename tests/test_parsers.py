import json
from datetime import date

from datetime import date, datetime

import pytest

from agent_access_review.parsers import REDACTED, _package, discover, is_reference, load
from conftest import EXAMPLES


@pytest.mark.parametrize('command,args,expected', [
    ('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
     ('@modelcontextprotocol/server-filesystem', False, ['/tmp'])),
    ('npx', ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://h/db'],
     ('@modelcontextprotocol/server-postgres', True, ['postgresql://h/db'])),
    ('npx', ['some-server@latest'], ('some-server', False, [])),
    ('npx.cmd', ['-y', 'some-server@1.2.3'], ('some-server', True, [])),
    ('uvx', ['mcp-server-fetch'], ('mcp-server-fetch', False, [])),
    ('uvx', ['mcp-server-fetch==2025.4.7'], ('mcp-server-fetch', True, [])),
    ('uvx', ['--from', 'mcp-server-git==0.6.2', 'mcp-server-git', '--repository', '/r'],
     ('mcp-server-git', True, ['/r'])),
    ('docker', ['run', '-i', '--rm', '-e', 'TOKEN', 'ghcr.io/github/github-mcp-server'],
     ('ghcr.io/github/github-mcp-server', False, [])),
    ('docker', ['run', '-i', 'ghcr.io/github/github-mcp-server:v1.0'],
     ('ghcr.io/github/github-mcp-server', False, [])),         # tags are mutable
    ('docker', ['run', 'localhost:5000/mcp@sha256:abc123'], ('localhost:5000/mcp', True, [])),
    ('python', ['server.py'], ('python', None, ['server.py'])),
])
def test_package_resolution(command, args, expected):
    assert _package(command, args) == expected


@pytest.mark.parametrize('value,ref', [
    ('${GITHUB_TOKEN}', True), ('${input:token}', True), ('$TOKEN', True), ('op://vault/item/field', True),
    ('<your-token>', True), ('', True), ('abc123secret', False), ('Bearer abc', False),
])
def test_is_reference(value, ref):
    assert is_reference(value) is ref


def test_claude_desktop_example():
    [agent] = load(EXAMPLES / 'claude_desktop_config.json')
    assert agent.source_type == 'mcp-config' and agent.owner is None
    by_tool = {g.tool: g for g in agent.grants}
    assert by_tool['filesystem'].scopes == ['/Users/dev']
    assert by_tool['customers-db'].pinned is True
    assert by_tool['customers-db'].data_classification == 'restricted'
    assert by_tool['terminal'].actions >= {'execute'}
    assert by_tool['internal-crm'].known is False
    hardcoded = sorted(c.name for c in agent.credentials if c.hardcoded)
    assert hardcoded == ['customers-db.connection-string', 'github.GITHUB_PERSONAL_ACCESS_TOKEN',
                         'internal-crm.arg.api-key']


def test_secrets_never_reach_the_inventory_or_evidence():
    [agent] = load(EXAMPLES / 'claude_desktop_config.json')
    text = repr(agent)
    for secret in ['example-not-a-real-token-0001', 'example-password', 'example-crm-key']:
        assert secret not in text
    assert agent.raw['mcpServers']['github']['env']['GITHUB_PERSONAL_ACCESS_TOKEN'] == REDACTED


def test_vscode_remote_servers():
    [agent] = load(EXAMPLES / 'vscode-mcp.json')
    by_tool = {g.tool: g for g in agent.grants}
    assert by_tool['github'].category == 'github' and by_tool['github'].known
    assert by_tool['jira'].endpoint.startswith('http://') and not by_tool['jira'].known
    assert not any(c.hardcoded for c in agent.credentials)     # ${input:...} references


def _manifest(tmp_path, body: str):
    path = tmp_path / 'agents.yaml'
    path.write_text('agents:\n'
                    '  - id: ops-agent\n'
                    '    name: Ops agent\n'
                    '    owner: platform-team\n'
                    '    approved_by: platform-team\n'
                    '    approved_on: 2026-10-01\n'
                    '    tools:\n'
                    '      - name: fs\n'
                    '        resource: disk\n' + body, encoding='utf-8')
    return load(path)[0].grants[0]


@pytest.mark.parametrize('field, value, expected', [
    ('actions', '[delete]', {'delete'}),
    ('actions', 'delete', {'delete'}),
    ('actions', 'execute', {'execute'}),
    ('scopes', '[repo]', ['repo']),
    ('scopes', 'repo', ['repo']),
    ('scopes', 'mail:*', ['mail:*']),
])
def test_a_list_field_may_hold_a_single_value(tmp_path, field, value, expected):
    """`actions: delete` used to become {'d','e','l','t','e'}: no privileged action at all."""
    g = _manifest(tmp_path, f'        {field}: {value}\n')
    assert getattr(g, field) == expected


@pytest.mark.parametrize('value, expected', [
    ('"false"', False), ('"no"', False), ('false', False),
    ('true', True), ('"true"', True), ('"yes"', True),
])
def test_a_flag_may_be_written_as_a_word(tmp_path, value, expected):
    """bool('false') is True, so a quoted false used to read as "sandboxed"."""
    assert _manifest(tmp_path, f'        actions: [execute]\n        sandboxed: {value}\n').sandboxed is expected


@pytest.mark.parametrize('field', ['untrusted_input', 'egress'])
def test_an_unrecognised_exfiltration_flag_counts_as_set(tmp_path, field):
    """For these two flags the answer that keeps AAR-09 firing is True, not False."""
    g = _manifest(tmp_path, f'        {field}: sometimes\n')
    assert getattr(g, field) is True


def test_an_unrecognised_flag_is_the_safe_answer(tmp_path):
    """A typo must not silence a check, so it falls back to "no approval, not sandboxed"."""
    g = _manifest(tmp_path, '        actions: [execute]\n        sandboxed: sometimes\n')
    assert g.sandboxed is False


def test_manifest_example():
    agents = {a.id: a for a in load(EXAMPLES / 'agents.yaml')}
    assert set(agents) == {'support-copilot', 'finance-ops-agent', 'devops-agent'}
    fin = agents['finance-ops-agent']
    assert fin.approved_on == date(2026, 3, 10)
    assert {c.name for c in fin.credentials} == {'netsuite.NETSUITE_TOKEN', 'sharepoint.GRAPH_CLIENT_SECRET'}
    assert agents['devops-agent'].credentials[0].hardcoded


def test_a_manifest_is_a_manifest_in_either_format(tmp_path, write_json):
    """The document decides the format, not the extension: this used to be YAML-only."""
    manifest = {'agents': [{'id': 'support-copilot', 'name': 'Support copilot', 'owner': 'platform',
                            'approved_by': 'platform', 'approved_on': '2026-10-12',
                            'tools': [{'name': 'tickets', 'resource': 'zendesk', 'actions': ['read']}]}]}
    as_json = write_json('agents.json', manifest)
    as_yaml = tmp_path / 'agents.yaml'
    as_yaml.write_text('agents:\n  - id: support-copilot\n    owner: platform\n', encoding='utf-8')
    [from_json] = load(as_json)
    [from_yaml] = load(as_yaml)
    assert from_json.id == from_yaml.id == 'support-copilot'
    assert from_json.approved_on == date(2026, 10, 12)
    assert [g.tool for g in from_json.grants] == ['tickets']


def test_a_manifest_may_write_a_full_timestamp(tmp_path):
    """YAML parses an unquoted timestamp into a datetime, which the checks cannot subtract."""
    manifest = tmp_path / 'agents.yaml'
    manifest.write_text('agents:\n'
                        '  - id: support-copilot\n'
                        '    owner: platform\n'
                        '    approved_on: 2026-10-12 09:00:00\n'
                        '    tools:\n'
                        '      - name: tickets\n'
                        '        last_used: 2026-10-10 17:30:00\n', encoding='utf-8')
    [agent] = load(manifest)
    assert agent.approved_on == date(2026, 10, 12)
    assert agent.grants[0].last_used == date(2026, 10, 10)
    assert not isinstance(agent.approved_on, datetime)


def test_discover_skips_unrelated_and_broken_files(tmp_path, write_json, capsys):
    write_json('package.json', {'name': 'x'})
    (tmp_path / 'broken.json').write_text('{"mcpServers": {', encoding='utf-8')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules' / 'mcp.json').write_text('{"mcpServers": {}}', encoding='utf-8')
    write_json('mcp.json', {'mcpServers': {'fetch': {'command': 'uvx', 'args': ['mcp-server-fetch']}}})
    agents = discover([tmp_path])
    assert [a.source.rsplit('/', 1)[-1] for a in agents] == ['mcp.json']
    assert 'skipped' in capsys.readouterr().err


def test_malformed_structures_are_reported_not_crashed(tmp_path, write_json, capsys):
    from agent_access_review.parsers import ConfigError
    # Found by fuzzing: a list where a server object belongs used to raise AttributeError,
    # which aborted the whole scan instead of skipping the one bad file.
    bad = write_json('mcp.json', {'mcpServers': {'fs': ['npx', 'server-filesystem']}})
    with pytest.raises(ConfigError, match='unexpected structure'):
        load(bad)
    manifest = tmp_path / 'agents.yaml'
    manifest.write_text('agents:\n  - name: no-id\n', encoding='utf-8')
    with pytest.raises(ConfigError):
        load(manifest)
    write_json('mcp-ok.json', {'mcpServers': {'fetch': {'command': 'uvx', 'args': ['mcp-server-fetch']}}})
    agents = discover([tmp_path])
    assert [a.id for a in agents] == ['mcp-ok'] and 'skipped' in capsys.readouterr().err


def test_discover_jsonc_mcp_config(tmp_path, capsys):
    folder = tmp_path / '.vscode'
    folder.mkdir()
    (folder / 'mcp.json').write_text('''// VS Code MCP configuration
{
  "servers": {
    /* Remote server */
    "github": {"url": "https://api.githubcopilot.com/mcp/",},
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch", /* trailing comma */],
    },
  },
} // end of config''', encoding='utf-8')
    [agent] = discover([tmp_path])
    grants = {g.tool: g for g in agent.grants}
    assert grants['github'].endpoint == 'https://api.githubcopilot.com/mcp/'
    assert grants['fetch'].package == 'mcp-server-fetch'
    assert capsys.readouterr().err == ''


def test_jsonc_preserves_string_contents(tmp_path):
    path = tmp_path / 'mcp.json'
    path.write_text(r'''{
      "servers": {"remote": {
        "url": "https://example.com/a//b/*literal*/?value=,}",
        "note": "escaped quote: \" // still a string,]",
        "path": "C:\\tools\\",
        "headers": {"Authorization": "Bearer example-test-secret"},
      }},
    }''', encoding='utf-8')
    [agent] = load(path)
    spec = agent.raw['servers']['remote']
    assert spec['url'] == 'https://example.com/a//b/*literal*/?value=,}'
    assert spec['note'] == 'escaped quote: " // still a string,]'
    assert spec['path'] == 'C:\\tools\\'
    assert spec['headers']['Authorization'] == REDACTED


@pytest.mark.parametrize('text', [
    '{"servers": { /* unclosed comment }',
    '{"servers": {"remote": {"url": "unterminated}}}',
    '{"servers": {},,}',
    '{"servers": {}, "number": 1/* comment */2}',
])
def test_jsonc_rejects_malformed_input(tmp_path, text):
    path = tmp_path / 'mcp.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError):
        load(path)


@pytest.mark.parametrize('args,expected', [
    (['run', '-i', '--rm', '--mount', 'type=bind,src=/Users/dev/Desktop,dst=/projects/Desktop',
      '--mount', 'type=bind,src=/data,dst=/projects/data,ro', 'mcp/filesystem', '/projects'],
     [('/Users/dev/Desktop', False), ('/data', True)]),
    (['run', '-v', r'C:\Users\dev:/home/dev:ro', '-v', 'claude-memory:/app/dist', 'mcp/memory'],
     [(r'C:\Users\dev', True)]),                       # Windows drive path kept; named volume ignored
    (['run', '--mount', 'type=bind,source=~/code,target=/code,readonly', 'img'], [('~/code', True)]),
])
def test_docker_mounts(args, expected):
    from agent_access_review.parsers import _docker_mounts
    assert _docker_mounts('docker', args) == expected


def test_official_docker_images_are_classified(write_json):
    # Found by scanning the official MCP READMEs: their Docker-based examples were unclassified.
    cfg = write_json('mcp.json', {'mcpServers': {
        'filesystem': {'command': 'docker', 'args': [
            'run', '-i', '--rm', '--mount', 'type=bind,src=/Users/dev,dst=/projects/home',
            '--mount', 'type=bind,src=/srv/docs,dst=/projects/docs,ro', 'mcp/filesystem', '/projects']},
        'docs': {'command': 'docker', 'args': [
            'run', '-i', '--rm', '--mount', 'type=bind,src=/srv/docs,dst=/projects/docs,ro', 'mcp/filesystem', '/projects']},
        'postgres': {'command': 'docker', 'args': ['run', '-i', '--rm', 'mcp/postgres', 'postgresql://db/app']},
        'git': {'command': 'uvx', 'args': ['mcp-server-git', '--repository', 'repo']},
    }})
    [agent] = load(cfg)
    g = {x.tool: x for x in agent.grants}
    assert all(x.known for x in g.values())
    assert g['filesystem'].scopes == ['/Users/dev', '/srv/docs']          # host paths, not /projects
    assert g['docs'].actions == {'read'}                                  # only read-only mounts
    assert g['postgres'].category == 'postgres' and g['git'].category == 'git'
    from agent_access_review.checks import run_all
    assert 'AAR-04' in {f.check_id for f in run_all(agent, date(2026, 10, 19)) if f.tool == 'filesystem'}

def test_catalog_classifies_sqlite_brave_gdrive(write_json):
    # https://github.com/Mihirajmera/agent-access-review/issues/4
    # These servers appear in many MCP configs but used to fall through as
    # unclassified (AAR-12); the catalog now carries their capability profiles.
    cfg = write_json('mcp.json', {'mcpServers': {
        'sqlite': {'command': 'uvx', 'args': ['mcp-server-sqlite', '--db-path', 'app.db']},
        'brave': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-brave-search']},
        'gdrive': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-gdrive']},
    }})
    [agent] = load(cfg)
    g = {x.tool: x for x in agent.grants}
    assert all(x.known for x in g.values()), 'all three servers must be classified, not AAR-12'
    assert g['sqlite'].category == 'sqlite'
    assert g['sqlite'].actions == {'read', 'write'}                       # read_query / write_query / create_table
    assert g['sqlite'].data_classification == 'confidential'
    assert g['brave'].category == 'brave-search'
    assert g['brave'].actions == {'read'}                                 # web/local search only
    assert g['brave'].egress and g['brave'].untrusted_input               # queries + results leave the org
    assert g['gdrive'].category == 'gdrive'
    assert g['gdrive'].actions == {'read'}                                # drive.readonly scope
    assert g['gdrive'].data_classification == 'confidential'


def test_discover_reads_configs_saved_with_a_byte_order_mark(tmp_path, capsys):
    # Notepad and PowerShell's Out-File write a BOM by default on Windows, and the epilog
    # points Windows users straight at %APPDATA%\Claude\claude_desktop_config.json. json.loads
    # rejected the BOM, discover() reported the file as skipped, and the host disappeared from
    # the review while the scan still exited 0.
    path = tmp_path / 'claude_desktop_config.json'
    path.write_bytes(b'\xef\xbb\xbf' + json.dumps({'mcpServers': {
        'filesystem': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem', '/']}}
    }).encode('utf-8'))
    [agent] = discover([tmp_path])
    assert agent.source_type == 'mcp-config'
    assert [g.tool for g in agent.grants] == ['filesystem']
    assert capsys.readouterr().err == ''


@pytest.mark.parametrize('args,flag,stored_last', [
    (['-y', '@modelcontextprotocol/server-git', '--token', 'ghp_live_secret_123'],
     'token', REDACTED),
    (['-y', '@modelcontextprotocol/server-git', '--token=ghp_live_secret_123'],
     'token', f'--token={REDACTED}'),
    (['server.py', '--api-key', 'sk-live-123'], 'api-key', REDACTED),
    (['server.py', '--db-password', 'hunter2'], 'db-password', REDACTED),
])
def test_secrets_separated_from_their_flag_are_still_caught(write_json, args, flag, stored_last):
    # SECRET_FLAG only matched "--token=value". The spaced form is what most CLIs document, and
    # it slipped through twice: no credential (so no AAR-06) and no redaction, which put the
    # literal secret in evidence/<agent>.json.
    cfg = write_json('mcp.json', {'mcpServers': {'git': {'command': 'npx', 'args': args}}})
    [agent] = load(cfg)
    assert [c.name for c in agent.credentials] == [f'git.arg.{flag}']
    assert all(c.hardcoded for c in agent.credentials)
    assert 'live_secret' not in repr(agent) and 'live-123' not in repr(agent)
    assert 'hunter2' not in repr(agent)
    stored = agent.raw['mcpServers']['git']['args']
    assert stored[-1] == stored_last


@pytest.mark.parametrize('args', [
    ['server.py', '--token', '${GITHUB_TOKEN}'],
    ['server.py', '--token', '$GITHUB_TOKEN'],
    ['server.py', '--token', 'op://vault/github/token'],
    ['server.py', '--token', '--verbose'],            # value missing, not an empty secret
])
def test_secret_flags_pointing_at_a_reference_are_left_alone(write_json, args):
    cfg = write_json('mcp.json', {'mcpServers': {'git': {'command': 'npx', 'args': args}}})
    [agent] = load(cfg)
    assert agent.credentials == []
    assert agent.raw['mcpServers']['git']['args'] == args


def test_hosts_in_different_folders_get_distinct_ids(tmp_path):
    # The id came from the file name alone, so two hosts both named claude_desktop_config.json
    # produced one id: evidence/<id>.json was written twice (second silently replaced the first)
    # and the OSCAL results kept only one observation of the two.
    for folder, package in (('laptop', 'server-filesystem'), ('desktop', 'server-git')):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / 'claude_desktop_config.json').write_text(json.dumps({'mcpServers': {
            folder: {'command': 'npx', 'args': ['-y', f'@modelcontextprotocol/{package}', '/']}}}),
            encoding='utf-8')
    agents = discover([tmp_path])
    assert len({a.id for a in agents}) == 2
    assert sorted(a.id.rsplit('-claude-desktop-config', 1)[0].rsplit('-', 1)[-1] for a in agents) \
        == ['desktop', 'laptop']


def test_a_unique_id_is_left_alone(tmp_path, write_json):
    write_json('alpha.json', {'mcpServers': {'fetch': {'command': 'uvx', 'args': ['mcp-server-fetch']}}})
    write_json('beta.json', {'mcpServers': {'fetch': {'command': 'uvx', 'args': ['mcp-server-fetch']}}})
    assert [a.id for a in discover([tmp_path])] == ['alpha', 'beta']

@pytest.mark.parametrize('url,param', [
    ('https://mcp.example.com/sse?api_key=sk-live-abc123', 'api_key'),
    ('https://mcp.example.com/sse?api-key=sk-live-abc123', 'api-key'),
    ('https://mcp.example.com/sse?apikey=sk-live-abc123', 'apikey'),
    ('https://mcp.example.com/sse?team=data&access_token=sk-live-abc123', 'access_token'),
    ('https://mcp.example.com/sse?value=1&client_secret=sk-live-abc123&page=2', 'client_secret'),
])
def test_a_secret_in_the_url_query_is_reported_and_masked(write_json, url, param):
    # A remote MCP server is configured by URL alone, so the query string is the only place a
    # token can sit. It used to reach access-review.md, access-review.csv and the evidence file
    # verbatim, and no check ever saw it.
    [agent] = load(write_json('mcp.json', {'mcpServers': {'remote': {'url': url}}}))
    assert [c.name for c in agent.credentials] == [f'remote.url.{param}']
    assert all(c.hardcoded for c in agent.credentials)
    assert 'sk-live-abc123' not in agent.grants[0].endpoint
    assert REDACTED in agent.grants[0].endpoint
    assert 'sk-live-abc123' not in agent.raw['mcpServers']['remote']['url']


def test_a_password_in_the_url_userinfo_is_reported_and_masked(write_json):
    [agent] = load(write_json('mcp.json', {
        'mcpServers': {'remote': {'url': 'https://svc:hunter2-REAL@mcp.example.com/sse'}}}))
    assert [c.name for c in agent.credentials] == ['remote.url.password']
    assert agent.grants[0].endpoint == f'https://svc:{REDACTED}@mcp.example.com/sse'
    assert agent.raw['mcpServers']['remote']['url'] == f'https://svc:{REDACTED}@mcp.example.com/sse'


@pytest.mark.parametrize('url', [
    'https://mcp.example.com/sse?api_key=${API_KEY}',        # points at a secret store
    'https://mcp.example.com/sse?access_token=$ACCESS_TOKEN',
    'https://mcp.example.com/sse?page=2&team=data',          # nothing secret at all
    'https://mcp.example.com/a//b/*literal*/?value=,}&page=2',   # query text that only looks odd
])
def test_urls_without_a_hardcoded_secret_are_left_alone(write_json, url):
    [agent] = load(write_json('mcp.json', {'mcpServers': {'remote': {'url': url}}}))
    assert agent.credentials == []
    assert agent.grants[0].endpoint == url
    assert agent.raw['mcpServers']['remote']['url'] == url


def test_a_url_secret_raises_a_hardcoded_credential_finding(write_json):
    from agent_access_review.checks import run_all
    [agent] = load(write_json('mcp.json', {
        'mcpServers': {'remote': {'url': 'https://mcp.example.com/sse?api_key=sk-live-abc123'}}}))
    assert 'AAR-06' in {f.check_id for f in run_all(agent, date(2026, 10, 12))}


def test_deprecated_reference_servers_carry_their_replacement(tmp_path):
    """The archived reference servers are flagged by package, Docker image and manifest alike."""
    cfg = tmp_path / 'claude_desktop_config.json'
    cfg.write_text(json.dumps({'mcpServers': {
        'gh': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github@2025.4.8']},
        'kv': {'command': 'docker', 'args': ['run', '-i', '--rm', 'mcp/redis', 'redis://host:6379']},
        'fs': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem@2025.8.21', '/tmp']},
    }}), encoding='utf-8')
    g = {x.tool: x for x in load(cfg)[0].grants}
    assert g['gh'].deprecated and g['gh'].replacement == 'ghcr.io/github/github-mcp-server'
    assert g['kv'].deprecated and g['kv'].replacement == 'redis-mcp-server'
    assert not g['fs'].deprecated


@pytest.mark.parametrize('value,fake', [
    ('YOUR_API_KEY', True), ('your-github-token-here', True), ('<token>', True), ('sk-xxxxxxxxxxxx', True),
    ('changeme', True), ('replace_with_your_key', True), ('********', True), ('aaaaaaaa', True),
    ('ghp_4fJ8kQ2mZ9xR7tL1vN3bC6dH0sW5yE8uP2aK', False), ('abcd1234efgh5678ijkl', False),
    ('test-key-123456789012', False), ('12345678', False),
])
def test_placeholders_are_not_reported_as_secrets(tmp_path, value, fake):
    """A template's `YOUR_API_KEY` isn't a leak; anything not obviously fake still is."""
    cfg = tmp_path / 'claude_desktop_config.json'
    cfg.write_text(json.dumps({'mcpServers': {'gh': {
        'command': 'npx', 'args': ['-y', 'some-mcp@1.0.0'], 'env': {'GITHUB_TOKEN': value}}}}), encoding='utf-8')
    [cred] = load(cfg)[0].credentials
    assert cred.hardcoded is not fake
