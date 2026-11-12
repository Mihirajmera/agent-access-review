"""Review outputs: a reviewer packet (Markdown), a UAR-style decision sheet (CSV),
hashed per-agent evidence (JSON) and OSCAL assessment results."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from .checks import CONTROLS, REGISTRY
from .model import SEVERITY_ORDER, Agent, Finding, Grant

FRAMEWORK_LABELS = {'nist_800_53': 'NIST 800-53', 'soc2': 'SOC 2', 'nist_ai_rmf': 'NIST AI RMF',
                    'owasp_llm': 'OWASP LLM'}


# --------------------------------------------------------------------------- helpers

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), default=_json_default)


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj).encode('utf-8')).hexdigest()


def _json_default(o):
    if isinstance(o, (date, datetime)):
        return o.isoformat()
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(type(o).__name__)


def inventory(agent: Agent) -> dict:
    d = asdict(agent)
    d.pop('raw')
    return json.loads(canonical(d))


def grant_decision(grant: Grant, findings: list[Finding]) -> str:
    """What the reviewer is asked to do with this grant."""
    mine = [f for f in findings if f.tool == grant.tool]
    if any(f.check_id == 'AAR-08' for f in mine):
        return 'Revoke'
    if any(f.check_id == 'AAR-12' for f in mine):
        return 'Investigate'
    if mine:
        return 'Modify'
    return 'Keep'


def counts(findings: list[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def _cell(value) -> str:
    """One markdown table cell. A pipe would start a new column and a bare CR would end the
    row, so both are neutralised; a config value can contain either."""
    return str(value).replace('|', '\\|').replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')


# A value a spreadsheet would treat as a formula rather than as text. Excel, LibreOffice and
# Sheets all evaluate a cell that starts with one of these, and a tool name comes straight out
# of the config being audited -- so an MCP server called "=cmd|'/c calc'!A1" runs when the
# reviewer opens the decision sheet.
FORMULA_LEAD = ('=', '+', '-', '@', '\t', '\r')


def _spreadsheet_cell(value) -> str:
    """Neutralise a value so a spreadsheet stores it as text, not as a formula."""
    text = str(value)
    if text.startswith(FORMULA_LEAD):
        return "'" + text
    return text


def _frameworks(check_id: str) -> str:
    c = CONTROLS[check_id]
    return '; '.join(f'{label} {", ".join(c[key])}' for key, label in FRAMEWORK_LABELS.items() if c.get(key))


# --------------------------------------------------------------------------- writers

def build_time() -> datetime:
    """Now, or SOURCE_DATE_EPOCH when set (the reproducible-builds convention), so a rerun on the
    same inputs can produce byte-identical output."""
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch:
        return datetime.fromtimestamp(int(epoch), timezone.utc)
    return datetime.now(timezone.utc).replace(microsecond=0)


def write_all(results: list[tuple[Agent, list[Finding]]], out: Path, as_of: date,
              collected: datetime | None = None) -> dict[str, Path]:
    collected = collected or build_time()
    out.mkdir(parents=True, exist_ok=True)
    evidence = write_evidence(results, out / 'evidence', as_of, collected)
    paths = {
        'report': write_markdown(results, out / 'access-review.md', as_of, evidence),
        'sheet': write_csv(results, out / 'access-review.csv'),
        'oscal': write_oscal(results, out / 'oscal' / 'assessment-results.json', as_of, collected, evidence),
    }
    paths.update({f'evidence:{k}': v[0] for k, v in evidence.items()})
    return paths


def write_evidence(results, folder: Path, as_of: date, collected: datetime) -> dict[str, tuple[Path, str]]:
    """One file per agent. The hash covers the inventory and the redacted source record,
    so any later edit to what the agent was found to have is detectable."""
    folder.mkdir(parents=True, exist_ok=True)
    index = {}
    for agent, findings in results:
        hashed = {'inventory': inventory(agent), 'source_record': agent.raw}
        record = {
            'agent_id': agent.id,
            'source': agent.source,
            'source_type': agent.source_type,
            'collected': collected.isoformat(),
            'review_as_of': as_of.isoformat(),
            **hashed,
            'results': [{
                'check_id': cid,
                'title': CONTROLS[cid]['title'],
                'status': 'FAIL' if any(f.check_id == cid for f in findings) else 'PASS',
                'findings': [asdict(f) for f in findings if f.check_id == cid],
            } for cid in sorted(REGISTRY)],
            'sha256': sha256(hashed),
            'hash_scope': 'sha256 of canonical JSON (sorted keys, no spaces) of {inventory, source_record}',
        }
        path = folder / f'{agent.id}.json'
        path.write_text(json.dumps(record, indent=2, sort_keys=True, default=_json_default) + '\n',
                        encoding='utf-8', newline='\n')
        index[agent.id] = (path, record['sha256'])
    return index


def write_csv(results, path: Path) -> Path:
    """One row per grant, in the shape of a user access review spreadsheet."""
    with path.open('w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh, lineterminator='\n')        # same bytes on every OS
        w.writerow(['agent_id', 'agent_name', 'owner', 'tool', 'category', 'resource', 'actions',
                    'data_classification', 'untrusted_input', 'egress', 'finding_ids',
                    'recommended_decision', 'reviewer_decision', 'reviewer', 'review_date'])
        for agent, findings in results:
            for g in agent.grants:
                ids = sorted({f.check_id for f in findings if f.tool == g.tool})
                w.writerow([_spreadsheet_cell(v) for v in [
                    agent.id, agent.name, agent.owner or '', g.tool, g.category or '', g.resource,
                    ' '.join(sorted(g.actions)), g.data_classification, g.untrusted_input,
                    g.egress, ' '.join(ids), grant_decision(g, findings), '', '', '']])
    return path


def write_markdown(results, path: Path, as_of: date, evidence: dict) -> Path:
    all_findings = [f for _, fs in results for f in fs]
    total = counts(all_findings)
    L = [f'# AI Agent Access Review: {as_of.isoformat()}', '',
         f'**{len(results)} agents**, **{sum(len(a.grants) for a, _ in results)} tool grants**, '
         f'**{len(all_findings)} findings** ({total["high"]} high, {total["medium"]} medium, {total["low"]} low).',
         '', '## Agents', '',
         '| Agent | Source | Owner | Approved | Tools | High | Medium | Low |',
         '|---|---|---|---|---:|---:|---:|---:|']
    for agent, findings in results:
        c = counts(findings)
        approved = f'{agent.approved_on} by {agent.approved_by}' if agent.approved_on else '**none**'
        L.append(f'| [{_cell(agent.name)}](#{agent.id}) | `{_cell(Path(agent.source).name)}` | '
                 f'{_cell(agent.owner or "**none**")} | {_cell(approved)} | {len(agent.grants)} | '
                 f'{c["high"]} | {c["medium"]} | {c["low"]} |')

    L += ['', '## Control results', '', '| Check | Control | Agents failing | Frameworks |', '|---|---|---:|---|']
    for cid in sorted(REGISTRY):
        failing = sum(1 for _, fs in results if any(f.check_id == cid for f in fs))
        L.append(f'| {cid} | {CONTROLS[cid]["title"]} | {failing} / {len(results)} | {_frameworks(cid)} |')

    for agent, findings in results:
        L += ['', '---', '', f'<a id="{agent.id}"></a>', f'## {_cell(agent.name)}', '',
              f'- **ID:** `{agent.id}` ({agent.source_type})',
              f'- **Source:** `{agent.source}`',
              f'- **Owner:** {agent.owner or "none recorded"}',
              f'- **Approval:** {f"{agent.approved_by} on {agent.approved_on}" if agent.approved_on else "none recorded"}',
              f'- **Evidence:** `evidence/{agent.id}.json` (sha256 `{evidence[agent.id][1][:16]}…`)',
              '', '### Access inventory', '',
              '| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |',
              '|---|---|---|---|---|:---:|:---:|---|---|']
        for g in agent.grants:
            L.append(f'| {_cell(g.tool)} | {_cell(g.category or ("unknown" if not g.known else "—"))} | `{_cell(g.resource)}` | '
                     f'{_cell(", ".join(sorted(g.actions)))} | {g.data_classification} | '
                     f'{"yes" if g.untrusted_input else ""} | {"yes" if g.egress else ""} | '
                     f'**{grant_decision(g, findings)}** | ☐ Keep ☐ Modify ☐ Revoke |')
        L += ['', '### Findings', '']
        if findings:
            L += ['| Check | Severity | Tool | Finding | Recommendation |', '|---|---|---|---|---|']
            for f in sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check_id)):
                L.append(f'| {f.check_id} | {f.severity} | {_cell(f.tool or "(agent)")} | '
                         f'{_cell(f.message)} | {_cell(f.recommendation)} |')
        else:
            L.append('No findings.')
        L += ['', '### Sign-off', '',
              'I have reviewed each tool grant above and confirm the decisions recorded.', '',
              '| Role | Name | Date |', '|---|---|---|',
              '| Agent owner | | |', '| Reviewer | | |']
    path.write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')
    return path


def _uid(*parts) -> str:
    """Deterministic UUID: the same review at the same time always gets the same IDs, and any
    change to the timestamp or subject gives new ones."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'agent-access-review:' + '/'.join(map(str, parts))))


def write_oscal(results, path: Path, as_of: date, collected: datetime, evidence: dict) -> Path:
    """OSCAL 1.1.2 assessment-results: one observation per agent, one finding per NIST
    800-53 control objective the checks map to."""
    path.parent.mkdir(parents=True, exist_ok=True)
    now = collected.isoformat()
    observations, obs_by_agent = [], {}
    for agent, findings in results:
        oid = _uid(now, 'observation', agent.id)
        obs_by_agent[agent.id] = oid
        ev_path, digest = evidence[agent.id]
        observations.append({
            'uuid': oid,
            'title': f'Access review of {agent.name}',
            'description': f'{len(agent.grants)} tool grants, {len(findings)} findings.',
            'methods': ['EXAMINE'],
            'types': ['finding' if findings else 'control-objective'],
            'subjects': [{'subject-uuid': str(uuid.uuid5(uuid.NAMESPACE_URL, agent.source + '#' + agent.id)),
                          'type': 'component', 'title': agent.name}],
            'relevant-evidence': [{'href': f'../evidence/{ev_path.name}', 'description': 'Hashed agent inventory',
                                   'props': [{'name': 'sha256', 'value': digest}]}],
            'collected': now,
        })

    by_control: dict[str, list[str]] = {}
    for cid in sorted(REGISTRY):
        for ctl in CONTROLS[cid]['nist_800_53']:
            by_control.setdefault(ctl, []).append(cid)
    oscal_findings = []
    for ctl, check_ids in sorted(by_control.items()):
        failing = [a.id for a, fs in results if any(f.check_id in check_ids for f in fs)]
        oscal_findings.append({
            'uuid': _uid(now, 'finding', ctl),
            'title': f'{ctl}: {", ".join(check_ids)}',
            'description': '; '.join(CONTROLS[c]['title'] for c in check_ids),
            'target': {'type': 'objective-id', 'target-id': ctl.lower().replace('(', '.').replace(')', ''),
                       'status': {'state': 'not-satisfied' if failing else 'satisfied'}},
            'related-observations': [{'observation-uuid': obs_by_agent[a]} for a in (failing or obs_by_agent)],
        })

    doc = {'assessment-results': {
        'uuid': _uid(now, 'assessment-results'),
        'metadata': {'title': 'AI agent access review', 'last-modified': now,
                     'version': as_of.isoformat(), 'oscal-version': '1.1.2'},
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uid(now, 'result'),
            'title': f'Agent access review as of {as_of.isoformat()}',
            'description': 'Automated review of AI agent tool access, credentials and approvals.',
            'start': now, 'end': now,
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': c.lower().replace('(', '.').replace(')', '')}
                                      for c in sorted(by_control)]}]},
            'observations': observations,
            'findings': oscal_findings,
        }],
    }}
    path.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8', newline='\n')
    return path
