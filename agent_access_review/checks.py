"""Access review checks. Each function takes one agent and the review date and returns
findings; an empty list means the control is satisfied for that agent."""
from __future__ import annotations

import ipaddress
import re
from datetime import date
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import yaml

from .model import SENSITIVE_DATA, Agent, Finding

CONTROLS = yaml.safe_load((Path(__file__).parent / 'controls.yaml').read_text(encoding='utf-8'))['controls']

RECERTIFY_DAYS = 90
ROTATE_DAYS = 90
DORMANT_DAYS = 90

# Filesystem roots and whole home directories: an agent with these can read SSH keys,
# browser profiles and cloud credentials.
BROAD_PATH = re.compile(r'^(/|~/?|/(Users|home)/[^/]+/?|[A-Za-z]:/?|[A-Za-z]:/Users/[^/]+/?)$', re.I)
IS_PATH = re.compile(r'^([A-Za-z]:|[/~.\\])')
# Wildcards, admin scopes, GitHub's full-control "repo" scope and tenant-wide Microsoft Graph "*.All" scopes.
BROAD_SCOPE = re.compile(r'^(\*|.*:\*|admin(:.*)?|.*:admin|repo|full_access|all|.*\.All)$', re.I)

CheckFn = Callable[[Agent, date], list[Finding]]
REGISTRY: dict[str, CheckFn] = {}


def check(check_id: str):
    def register(fn: CheckFn) -> CheckFn:
        REGISTRY[check_id] = fn
        return fn
    return register


def run_all(agent: Agent, as_of: date) -> list[Finding]:
    return [f for cid in sorted(REGISTRY) for f in REGISTRY[cid](agent, as_of)]


# A plain-HTTP endpoint on the machine itself never leaves the host, so there is no traffic to
# encrypt. Everything else over HTTP is a finding.
LOOPBACK_HOSTS = {'localhost', '127.0.0.1', '::1'}


def is_loopback(url: str) -> bool:
    """True when the URL points at the local machine.

    The host has to come from urlsplit: a regex over the string reads the userinfo as the host,
    so `http://127.0.0.1:80@evil.example.com/` looked local while it connects to evil.example.com.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:                       # malformed authority, e.g. an unclosed IPv6 bracket
        return False
    if not host:
        return False
    host = host.lower().rstrip('.')
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@check('AAR-01')
def owner(agent: Agent, as_of: date) -> list[Finding]:
    if agent.owner:
        return []
    return [Finding('AAR-01', 'high', agent.id,
                    'No accountable human owner is recorded for this agent.',
                    'Assign an owner who answers for what the agent does, or decommission it.')]


@check('AAR-02')
def approval(agent: Agent, as_of: date) -> list[Finding]:
    if not agent.approved_by or not agent.approved_on:
        return [Finding('AAR-02', 'high', agent.id,
                        'Agent access has no recorded approval.',
                        'Route the agent through access approval before its next use.')]
    age = (as_of - agent.approved_on).days
    if age > RECERTIFY_DAYS:
        return [Finding('AAR-02', 'medium', agent.id,
                        f'Access was last approved {age} days ago by {agent.approved_by} '
                        f'(limit {RECERTIFY_DAYS}).',
                        'Recertify: the owner confirms each tool below is still needed.')]
    return []


@check('AAR-03')
def human_in_the_loop(agent: Agent, as_of: date) -> list[Finding]:
    out = []
    for g in agent.grants:
        priv = g.privileged - {'execute'}            # execute is covered by AAR-05
        if not priv or g.requires_approval:
            continue
        severe = bool(priv & {'delete', 'admin'}) or g.data_classification in SENSITIVE_DATA
        out.append(Finding('AAR-03', 'high' if severe else 'medium', agent.id,
                           f'{g.tool} can {" / ".join(sorted(priv))} {g.data_classification} data '
                           f'without a human approving each action.',
                           'Require human confirmation for these actions, or reduce the tool to read-only.',
                           tool=g.tool))
    return out


@check('AAR-04')
def least_privilege(agent: Agent, as_of: date) -> list[Finding]:
    out = []
    for g in agent.grants:
        broad = [s for s in g.scopes
                 if (BROAD_PATH.match(s.replace('\\', '/')) if IS_PATH.match(s) else BROAD_SCOPE.match(s))]
        if 'admin' in g.actions:
            broad.append('admin action')
        if broad:
            out.append(Finding('AAR-04', 'high', agent.id,
                               f'Over-broad access on {g.tool}: {", ".join(broad)}.',
                               'Narrow the grant to the specific directories, repositories or scopes '
                               'the agent needs.', tool=g.tool))
    return out


@check('AAR-05')
def sandboxed_execution(agent: Agent, as_of: date) -> list[Finding]:
    return [Finding('AAR-05', 'high', agent.id,
                    f'{g.tool} can execute arbitrary commands on the host without a sandbox.',
                    'Run the tool in a container or VM with no host credentials mounted, '
                    'or remove it.', tool=g.tool)
            for g in agent.grants if 'execute' in g.actions and not g.sandboxed]


@check('AAR-06')
def hardcoded_credentials(agent: Agent, as_of: date) -> list[Finding]:
    return [Finding('AAR-06', 'high', agent.id,
                    f'Credential {c.name} is stored in plain text in the agent configuration.',
                    'Revoke and reissue it, then load it from a secret manager or environment reference.',
                    tool=c.name.split('.', 1)[0])
            for c in agent.credentials if c.hardcoded]


@check('AAR-07')
def credential_rotation(agent: Agent, as_of: date) -> list[Finding]:
    out = []
    for c in agent.credentials:
        if c.hardcoded:
            continue                                 # AAR-06 already requires reissuing it
        if c.last_rotated is None:
            out.append(Finding('AAR-07', 'low', agent.id,
                               f'No rotation date is recorded for {c.name}.',
                               'Record when the credential was issued so rotation can be evidenced.',
                               tool=c.name.split('.', 1)[0]))
        elif (age := (as_of - c.last_rotated).days) > ROTATE_DAYS:
            out.append(Finding('AAR-07', 'medium', agent.id,
                               f'{c.name} was last rotated {age} days ago (limit {ROTATE_DAYS}).',
                               'Rotate the credential.', tool=c.name.split('.', 1)[0]))
    return out


@check('AAR-08')
def dormant_access(agent: Agent, as_of: date) -> list[Finding]:
    if agent.grants and all(g.last_used is None for g in agent.grants):
        return [Finding('AAR-08', 'low', agent.id,
                        'No tool usage is logged, so dormant access cannot be identified.',
                        'Log tool calls per agent so unused access can be found and removed.')]
    return [Finding('AAR-08', 'medium', agent.id,
                    f'{g.tool} has not been used for {(as_of - g.last_used).days} days.',
                    'Revoke this tool; re-request it if it is needed again.', tool=g.tool)
            for g in agent.grants
            if g.last_used is not None and (as_of - g.last_used).days > DORMANT_DAYS]


@check('AAR-09')
def exfiltration_path(agent: Agent, as_of: date) -> list[Finding]:
    """Sensitive data + attacker-controlled input + a way out = one prompt injection away from a breach."""
    sensitive = [g for g in agent.grants if g.data_classification in SENSITIVE_DATA]
    untrusted = [g for g in agent.grants if g.untrusted_input and not g.requires_approval]
    egress = [g for g in agent.grants if g.egress and not g.requires_approval]
    if not (sensitive and untrusted and egress):
        return []
    names = lambda gs: ', '.join(sorted({g.tool for g in gs}))
    return [Finding('AAR-09', 'high', agent.id,
                    f'Exfiltration path: reads sensitive data ({names(sensitive)}), ingests untrusted '
                    f'content ({names(untrusted)}) and can send data out ({names(egress)}) with no '
                    f'human approval. A prompt injection in the untrusted content could leak the data.',
                    'Break the chain: split the agent, remove one leg, or require approval on '
                    'every egress action.')]


@check('AAR-10')
def pinned_packages(agent: Agent, as_of: date) -> list[Finding]:
    return [Finding('AAR-10', 'medium', agent.id,
                    f'{g.tool} runs {g.package} without a pinned version, so a new upstream release '
                    f'runs automatically.',
                    'Pin an exact version (npm/PyPI) or image digest and update it through change control.',
                    tool=g.tool)
            for g in agent.grants if g.pinned is False]


@check('AAR-11')
def encrypted_transport(agent: Agent, as_of: date) -> list[Finding]:
    out = []
    for g in agent.grants:
        if not g.endpoint or not g.endpoint.lower().startswith('http://'):
            continue
        if is_loopback(g.endpoint):
            continue
        out.append(Finding('AAR-11', 'high', agent.id,
                           f'{g.tool} connects to {g.endpoint} over unencrypted HTTP.',
                           'Use HTTPS so credentials and tool traffic are encrypted in transit.',
                           tool=g.tool))
    return out


@check('AAR-12')
def capability_inventory(agent: Agent, as_of: date) -> list[Finding]:
    return [Finding('AAR-12', 'medium', agent.id,
                    f'{g.tool} ({g.resource}) is not in the capability catalog, so its access '
                    f'cannot be assessed.',
                    'Document what the tool can read, write and send, and add it to catalog.yaml.',
                    tool=g.tool)
            for g in agent.grants if not g.known]
