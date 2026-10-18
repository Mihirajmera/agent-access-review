from datetime import date

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


def test_manifest_example():
    agents = {a.id: a for a in load(EXAMPLES / 'agents.yaml')}
    assert set(agents) == {'support-copilot', 'finance-ops-agent', 'devops-agent'}
    fin = agents['finance-ops-agent']
    assert fin.approved_on == date(2026, 3, 10)
    assert {c.name for c in fin.credentials} == {'netsuite.NETSUITE_TOKEN', 'sharepoint.GRAPH_CLIENT_SECRET'}
    assert agents['devops-agent'].credentials[0].hardcoded


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
