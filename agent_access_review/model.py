"""Normalized inventory model. Every input format (MCP configs, agent manifests) is
parsed into these classes so the checks never care where an agent came from."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

# Actions that change state or move data. Anything outside {"read"} is privileged.
PRIVILEGED_ACTIONS = {'write', 'delete', 'send', 'execute', 'admin'}
SENSITIVE_DATA = {'confidential', 'restricted'}
SEVERITY_ORDER = {'high': 3, 'medium': 2, 'low': 1}


@dataclass
class Grant:
    """One tool or MCP server the agent can call, and what it can do with it."""
    tool: str
    resource: str
    actions: set[str]
    scopes: list[str] = field(default_factory=list)
    data_classification: str = 'internal'   # public | internal | confidential | restricted
    untrusted_input: bool = False            # reads content an outsider can write (web, tickets, email)
    egress: bool = False                     # can send data outside the organization
    requires_approval: bool = False          # a human approves each privileged call
    sandboxed: bool = False
    last_used: date | None = None
    package: str | None = None               # npm / PyPI / container reference it runs from
    pinned: bool | None = None               # None = not a package (local code), so not assessable
    endpoint: str | None = None              # remote MCP URL
    known: bool = True                       # False when capabilities could not be classified
    category: str | None = None              # capability profile from catalog.yaml (filesystem, shell, ...)
    deprecated: bool = False                 # the package is deprecated or its repository archived
    replacement: str | None = None           # the maintained server to move to, when there is one

    @property
    def privileged(self) -> set[str]:
        return self.actions & PRIVILEGED_ACTIONS


@dataclass
class Credential:
    name: str
    hardcoded: bool
    last_rotated: date | None = None


@dataclass
class Agent:
    id: str
    name: str
    source: str                              # file the agent was discovered in
    source_type: str                         # mcp-config | agent-manifest
    owner: str | None = None
    approved_by: str | None = None
    approved_on: date | None = None
    grants: list[Grant] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # redacted source record, kept as evidence


@dataclass
class Finding:
    check_id: str
    severity: str                            # high | medium | low
    agent_id: str
    message: str
    recommendation: str
    tool: str | None = None                  # None = applies to the whole agent
