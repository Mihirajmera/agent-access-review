"""CLI.

  agent-access-review demo                       review the bundled example agents
  agent-access-review scan <paths> [--out review] [--as-of YYYY-MM-DD] [--fail-on high] [--format json]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .checks import run_all
from .model import SEVERITY_ORDER
from .parsers import discover
from .report import counts, write_all

EXAMPLES = Path(__file__).parent / 'examples'
EXAMPLES_AS_OF = date(2026, 10, 12)        # the date the bundled examples were written for

EPILOG = """examples:
  agent-access-review demo
  agent-access-review scan ~/Library/Application\\ Support/Claude/claude_desktop_config.json
  agent-access-review scan %APPDATA%\\Claude\\claude_desktop_config.json      (Windows cmd)
  agent-access-review scan ~/.cursor/mcp.json .vscode/mcp.json agents.yaml --fail-on high
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='agent-access-review',
                                 description='Access reviews for AI agents and MCP servers.',
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    scan = sub.add_parser('scan', help='review agent configs and write the review packet')
    scan.add_argument('paths', nargs='+', type=Path, help='MCP config files, agents.yaml manifests, or folders')
    scan.add_argument('--out', type=Path, default=Path('review'), help='output folder (default: review)')
    scan.add_argument('--as-of', type=date.fromisoformat, default=date.today(),
                      help='review date used for recertification, rotation and dormancy (default: today)')
    scan.add_argument('--fail-on', choices=['high', 'medium', 'low', 'never'], default='never',
                      help='exit 1 if any finding is at or above this severity (for CI gates)')
    scan.add_argument('--format', choices=['json'], default=None,
                      help='print each agent\'s findings as one JSON document on stdout (files are still written)')
    demo = sub.add_parser('demo', help='review the bundled example agents (no setup needed)')
    demo.add_argument('--out', type=Path, default=Path('review-demo'), help='output folder (default: review-demo)')
    args = ap.parse_args(argv)

    if args.cmd == 'demo':
        print(f'Reviewing the bundled examples in {EXAMPLES} (as of {EXAMPLES_AS_OF}):\n')
        return run([EXAMPLES], args.out, EXAMPLES_AS_OF, 'never', demo=True)

    missing = [p for p in args.paths if not p.exists()]
    if missing:
        ap.error(f'not found: {", ".join(map(str, missing))}')
    return run(args.paths, args.out, args.as_of, args.fail_on, fmt=getattr(args, 'format', None))


def run(paths: list[Path], out: Path, as_of: date, fail_on: str, demo: bool = False,
        fmt: str | None = None) -> int:
    agents = discover(paths)
    if not agents:
        print('No MCP configs or agent manifests found.', file=sys.stderr)
        return 2

    results = [(a, run_all(a, as_of)) for a in agents]
    written = write_all(results, out, as_of)

    if fmt == 'json':
        payload = {
            'as_of': as_of.isoformat(),
            'agents': [
                {
                    'agent': agent.id,
                    'tools': len(agent.grants),
                    'findings': [
                        {
                            'check_id': f.check_id,
                            'severity': f.severity,
                            'tool': f.tool,
                            'message': f.message,
                            'recommendation': f.recommendation,
                        }
                        for f in findings
                    ],
                }
                for agent, findings in results
            ],
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write('\n')
        return _exit_code(results, fail_on)

    print(f'{"AGENT":<28} {"TOOLS":>5} {"HIGH":>5} {"MED":>5} {"LOW":>5}')
    for agent, findings in results:
        c = counts(findings)
        print(f'{agent.id[:28]:<28} {len(agent.grants):>5} {c["high"]:>5} {c["medium"]:>5} {c["low"]:>5}')
    print(f'\nReview packet: {written["report"]}\nDecision sheet: {written["sheet"]}\nOSCAL: {written["oscal"]}')
    if demo:
        print('\nOpen the review packet to see each agent\'s access, findings and recommended decisions.'
              '\nNext: run `agent-access-review scan <your MCP config>` on your own setup.')

    return _exit_code(results, fail_on)


def _exit_code(results: list[tuple], fail_on: str) -> int:
    if fail_on != 'never':
        floor = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[f.severity] >= floor for _, fs in results for f in fs):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
