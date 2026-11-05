from datetime import date

from agent_access_review.checks import REGISTRY, run_all
from agent_access_review.model import Credential, Grant


def ids(findings):
    return sorted({f.check_id for f in findings})


def test_governed_agent_passes_every_check(governed_agent, as_of):
    assert run_all(governed_agent, as_of) == []


def test_every_control_has_a_check():
    assert sorted(REGISTRY) == [f'AAR-{i:02d}' for i in range(1, 13)]


def test_missing_owner(governed_agent, as_of):
    governed_agent.owner = None
    assert ids(run_all(governed_agent, as_of)) == ['AAR-01']


def test_missing_approval_is_high(governed_agent, as_of):
    governed_agent.approved_on = None
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.severity) == ('AAR-02', 'high')


def test_stale_approval_needs_recertification(governed_agent, as_of):
    governed_agent.approved_on = date(2026, 7, 13)          # 91 days
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.severity) == ('AAR-02', 'medium')
    governed_agent.approved_on = date(2026, 7, 14)          # 90 days is still in policy
    assert run_all(governed_agent, as_of) == []


def test_write_without_human_approval(governed_agent, as_of):
    governed_agent.grants[0].actions = {'read', 'write'}
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.severity) == ('AAR-03', 'medium')  # internal data
    governed_agent.grants[0].data_classification = 'restricted'
    assert run_all(governed_agent, as_of)[0].severity == 'high'
    governed_agent.grants[0].requires_approval = True
    assert run_all(governed_agent, as_of) == []


def test_broad_paths_and_scopes(governed_agent, as_of):
    g = governed_agent.grants[0]
    for scope in ['/', '~', '/Users/dev', '/home/dev/', 'C:\\', 'C:\\Users\\dev', '*', 'repo',
                  'admin:org', 'Sites.Read.All']:
        g.scopes = [scope]
        assert ids(run_all(governed_agent, as_of)) == ['AAR-04'], scope
    for scope in ['/Users/dev/projects/app', 'C:\\Users\\dev\\projects', 'read:org', 'public_repo']:
        g.scopes = [scope]
        assert run_all(governed_agent, as_of) == [], scope


def test_unsandboxed_execution(governed_agent, as_of):
    governed_agent.grants[0].actions = {'execute'}
    assert ids(run_all(governed_agent, as_of)) == ['AAR-05']
    governed_agent.grants[0].sandboxed = True
    assert run_all(governed_agent, as_of) == []


def test_hardcoded_credential_is_not_also_flagged_for_rotation(governed_agent, as_of):
    governed_agent.credentials = [Credential('kb.TOKEN', hardcoded=True, last_rotated=date(2020, 1, 1))]
    assert ids(run_all(governed_agent, as_of)) == ['AAR-06']


def test_credential_rotation(governed_agent, as_of):
    governed_agent.credentials[0].last_rotated = date(2026, 1, 1)
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.severity) == ('AAR-07', 'medium')
    governed_agent.credentials[0].last_rotated = None
    assert run_all(governed_agent, as_of)[0].severity == 'low'


def test_dormant_tool_is_flagged_for_revocation(governed_agent, as_of):
    governed_agent.grants[0].last_used = date(2026, 6, 1)
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.tool) == ('AAR-08', 'kb')


def test_no_usage_telemetry(governed_agent, as_of):
    governed_agent.grants[0].last_used = None
    [f] = run_all(governed_agent, as_of)
    assert (f.check_id, f.severity, f.tool) == ('AAR-08', 'low', None)


def test_exfiltration_path_needs_all_three_legs(governed_agent, as_of):
    recent = date(2026, 10, 10)
    governed_agent.grants = [
        Grant('db', 'postgres:prod', {'read'}, data_classification='restricted', last_used=recent),
        Grant('inbox', 'mail', {'read'}, untrusted_input=True, last_used=recent),
        Grant('web', 'fetch', {'read'}, egress=True, last_used=recent),
    ]
    assert ids(run_all(governed_agent, as_of)) == ['AAR-09']
    governed_agent.grants[2].requires_approval = True       # human gate on the way out
    assert run_all(governed_agent, as_of) == []
    governed_agent.grants[2].requires_approval = False
    governed_agent.grants.pop(0)                            # nothing sensitive to steal
    assert run_all(governed_agent, as_of) == []


def test_unpinned_package(governed_agent, as_of):
    governed_agent.grants[0].package, governed_agent.grants[0].pinned = 'some-mcp', False
    assert ids(run_all(governed_agent, as_of)) == ['AAR-10']
    governed_agent.grants[0].pinned = None                  # local code: not assessable
    assert run_all(governed_agent, as_of) == []


def test_plain_http_remote(governed_agent, as_of):
    g = governed_agent.grants[0]
    g.endpoint = 'http://mcp.example.com/sse'
    assert ids(run_all(governed_agent, as_of)) == ['AAR-11']
    for ok in ['https://mcp.example.com/sse', 'http://localhost:3000/mcp', 'http://127.0.0.1:8080']:
        g.endpoint = ok
        assert run_all(governed_agent, as_of) == [], ok


def test_every_loopback_spelling_is_exempt(governed_agent, as_of):
    g = governed_agent.grants[0]
    for local in ['http://[::1]:8080/sse', 'http://[0:0:0:0:0:0:0:1]/sse',
                  'http://LOCALHOST./sse', 'http://127.0.0.2:9/sse']:
        g.endpoint = local
        assert run_all(governed_agent, as_of) == [], local


def test_a_remote_host_cannot_hide_in_the_userinfo(governed_agent, as_of):
    """A regex over the raw string reads `127.0.0.1` as the host here; urlsplit reads the real one."""
    g = governed_agent.grants[0]
    for spoof in ['http://127.0.0.1:80@evil.example.com/sse', 'http://localhost@evil.example.com/sse']:
        g.endpoint = spoof
        assert ids(run_all(governed_agent, as_of)) == ['AAR-11'], spoof


def test_unclassified_tool(governed_agent, as_of):
    governed_agent.grants[0].known = False
    assert ids(run_all(governed_agent, as_of)) == ['AAR-12']
