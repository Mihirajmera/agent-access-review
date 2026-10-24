"""CLI tests: `scan --format json` prints a consumable JSON document."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / 'agent_access_review' / 'examples'


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-m', 'agent_access_review', *args],
                          cwd=REPO, capture_output=True, text=True, encoding='utf-8')


def test_scan_format_json_prints_findings(tmp_path: Path) -> None:
    out = tmp_path / 'review'
    proc = run_cli('scan', str(EXAMPLES / 'agents.yaml'), '--out', str(out), '--format', 'json')

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)

    assert payload['as_of']  # ISO date string
    agents = payload['agents']
    assert agents, 'expected at least one agent in the JSON output'

    for entry in agents:
        assert entry['agent'], 'agent id must be a non-empty string'
        assert isinstance(entry['tools'], int)
        for finding in entry['findings']:
            assert finding['check_id']
            assert finding['severity'] in ('high', 'medium', 'low')
            assert finding['tool'] is None or isinstance(finding['tool'], str)
            assert finding['message']
            assert finding['recommendation']

    # the review packet files are still written alongside the JSON output
    assert (out / 'access-review.md').exists()
    assert (out / 'access-review.csv').exists()


def test_scan_format_json_fail_on_exit_code(tmp_path: Path) -> None:
    out = tmp_path / 'review'
    proc = run_cli('scan', str(EXAMPLES / 'agents.yaml'), '--out', str(out),
                   '--format', 'json', '--fail-on', 'low')

    # the bundled examples carry at least one low-or-above finding, so the
    # CI gate must fail (exit 1) even in JSON mode, with valid JSON on stdout.
    assert proc.returncode == 1, proc.stderr
    payload = json.loads(proc.stdout)
    assert any(entry['findings'] for entry in payload['agents'])


def test_scan_default_output_unchanged(tmp_path: Path) -> None:
    out = tmp_path / 'review'
    proc = run_cli('scan', str(EXAMPLES / 'agents.yaml'), '--out', str(out))

    assert proc.returncode == 0, proc.stderr
    with pytest.raises(json.JSONDecodeError):
        json.loads(proc.stdout)
    assert 'AGENT' in proc.stdout  # the human-readable table is still the default
