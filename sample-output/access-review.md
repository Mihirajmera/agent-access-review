# AI Agent Access Review: 2026-10-12

**5 agents**, **17 tool grants**, **44 findings** (28 high, 11 medium, 5 low).

## Agents

| Agent | Source | Owner | Approved | Tools | High | Medium | Low |
|---|---|---|---|---:|---:|---:|---:|
| [Customer Support Copilot](#support-copilot) | `agents.yaml` | priya.shah@example.com | 2026-08-20 by ai-review-board | 2 | 0 | 0 | 0 |
| [Finance Ops Agent](#finance-ops-agent) | `agents.yaml` | marco.diaz@example.com | 2026-03-10 by cfo-office | 4 | 4 | 3 | 0 |
| [DevOps Auto-Remediation Agent](#devops-agent) | `agents.yaml` | **none** | **none** | 2 | 6 | 1 | 1 |
| [MCP host (claude_desktop_config.json)](#claude-desktop-config) | `claude_desktop_config.json` | **none** | **none** | 6 | 12 | 5 | 1 |
| [MCP host (vscode-mcp.json)](#vscode-mcp) | `vscode-mcp.json` | **none** | **none** | 3 | 6 | 2 | 3 |

## Control results

| Check | Control | Agents failing | Frameworks |
|---|---|---:|---|
| AAR-01 | Every agent has an accountable human owner | 3 / 5 | NIST 800-53 AC-2; SOC 2 CC6.2; NIST AI RMF GOVERN 2.1 |
| AAR-02 | Agent access is approved and recertified within 90 days | 4 / 5 | NIST 800-53 AC-2; SOC 2 CC6.2, CC6.3 |
| AAR-03 | Privileged agent actions require human approval | 4 / 5 | NIST 800-53 AC-6; SOC 2 CC6.3; NIST AI RMF MAP 3.5; OWASP LLM LLM06 |
| AAR-04 | Tool scopes follow least privilege | 3 / 5 | NIST 800-53 AC-6; SOC 2 CC6.3; OWASP LLM LLM06 |
| AAR-05 | Code and shell execution is sandboxed | 2 / 5 | NIST 800-53 CM-7, AC-6; OWASP LLM LLM05, LLM06 |
| AAR-06 | No credentials are hardcoded in agent configuration | 2 / 5 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-07 | Agent credentials are rotated within 90 days | 2 / 5 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-08 | Dormant agent access is removed after 90 days | 4 / 5 | NIST 800-53 AC-2(3); SOC 2 CC6.2 |
| AAR-09 | No unmitigated data exfiltration path | 3 / 5 | NIST 800-53 AC-4; NIST AI RMF MEASURE 2.7; OWASP LLM LLM01, LLM02 |
| AAR-10 | Tool packages are pinned to a version | 2 / 5 | NIST 800-53 SR-3; OWASP LLM LLM03 |
| AAR-11 | Remote tools use encrypted transport | 1 / 5 | NIST 800-53 SC-8; SOC 2 CC6.7 |
| AAR-12 | Every tool's capabilities are inventoried | 2 / 5 | NIST 800-53 CM-8; NIST AI RMF GOVERN 1.6 |
| AAR-13 | Tool servers are still maintained upstream | 1 / 5 | NIST 800-53 SA-22, SI-2; SOC 2 CC7.1; OWASP LLM LLM03 |
| AAR-14 | Tool servers have no known vulnerabilities | 1 / 5 | NIST 800-53 RA-5, SI-2; SOC 2 CC7.1; OWASP LLM LLM03 |

---

<a id="support-copilot"></a>
## Customer Support Copilot

- **ID:** `support-copilot` (agent-manifest)
- **Source:** `examples/agents.yaml`
- **Owner:** priya.shah@example.com
- **Approval:** ai-review-board on 2026-08-20
- **Evidence:** `evidence/support-copilot.json` (sha256 `a36f6c6dac3a3160…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| zendesk | ticketing | `zendesk:tickets` | read, write | confidential | yes |  | **Keep** | ☐ Keep ☐ Modify ☐ Revoke |
| kb-search | knowledge-base | `confluence:space/SUPPORT` | read | internal |  |  | **Keep** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

No findings.

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="finance-ops-agent"></a>
## Finance Ops Agent

- **ID:** `finance-ops-agent` (agent-manifest)
- **Source:** `examples/agents.yaml`
- **Owner:** marco.diaz@example.com
- **Approval:** cfo-office on 2026-03-10
- **Evidence:** `evidence/finance-ops-agent.json` (sha256 `408c88220a34b7e1…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| netsuite | erp | `netsuite:vendor-bills` | read, write | restricted |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| outlook | email | `mailbox:ap@example.com` | read, send | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| sharepoint | document-store | `sharepoint:finance` | read | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| expense-ocr | ocr | `ocr-service:receipts` | read | confidential |  |  | **Revoke** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-03 | high | netsuite | netsuite can write restricted data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | outlook | outlook can send confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-04 | high | sharepoint | Over-broad access on sharepoint: Sites.Read.All. | Narrow the grant to the specific directories, repositories or scopes the agent needs. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (expense-ocr, netsuite, outlook, sharepoint), ingests untrusted content (outlook) and can send data out (outlook) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-02 | medium | (agent) | Access was last approved 216 days ago by cfo-office (limit 90). | Recertify: the owner confirms each tool below is still needed. |
| AAR-07 | medium | netsuite | netsuite.NETSUITE_TOKEN was last rotated 315 days ago (limit 90). | Rotate the credential. |
| AAR-08 | medium | expense-ocr | expense-ocr has not been used for 164 days. | Revoke this tool; re-request it if it is needed again. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="devops-agent"></a>
## DevOps Auto-Remediation Agent

- **ID:** `devops-agent` (agent-manifest)
- **Source:** `examples/agents.yaml`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/devops-agent.json` (sha256 `36fe6d2a99d28c1f…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| shell | shell | `build-runner-07` | execute | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| github | source-control | `github:acme-corp` | read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | github | github can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-04 | high | github | Over-broad access on github: repo. | Narrow the grant to the specific directories, repositories or scopes the agent needs. |
| AAR-05 | high | shell | shell can execute arbitrary commands on the host without a sandbox. | Run the tool in a container or VM with no host credentials mounted, or remove it. |
| AAR-06 | high | github | Credential github.GITHUB_TOKEN is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-10 | medium | github | github runs @acme/github-tools without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="claude-desktop-config"></a>
## MCP host (claude_desktop_config.json)

- **ID:** `claude-desktop-config` (mcp-config)
- **Source:** `examples/claude_desktop_config.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/claude-desktop-config.json` (sha256 `c66e5b2c081095ab…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| filesystem | filesystem | `/Users/dev` | delete, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| github | github | `ghcr.io/github/github-mcp-server` | read, write | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| fetch | fetch | `mcp-server-fetch` | read | public | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| customers-db | postgres | `postgresql://analyst:***REDACTED***@db.internal:5432/customers` | read | restricted |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| terminal | shell | `@wonderwhy-er/desktop-commander` | delete, execute, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| internal-crm | unknown | `python /opt/tools/crm_server.py --api-key=***REDACTED***` | unknown | internal |  |  | **Investigate** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | filesystem | filesystem can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | github | github can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | terminal | terminal can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-04 | high | filesystem | Over-broad access on filesystem: /Users/dev. | Narrow the grant to the specific directories, repositories or scopes the agent needs. |
| AAR-05 | high | terminal | terminal can execute arbitrary commands on the host without a sandbox. | Run the tool in a container or VM with no host credentials mounted, or remove it. |
| AAR-06 | high | github | Credential github.GITHUB_PERSONAL_ACCESS_TOKEN is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-06 | high | customers-db | Credential customers-db.connection-string is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-06 | high | internal-crm | Credential internal-crm.arg.api-key is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (customers-db, filesystem, github, terminal), ingests untrusted content (fetch, github) and can send data out (fetch, github) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-13 | high | customers-db | customers-db runs @modelcontextprotocol/server-postgres, which is deprecated or archived upstream and no longer receives security fixes. | No maintained replacement is listed: find one, or remove this server and record the decision. |
| AAR-10 | medium | filesystem | filesystem runs @modelcontextprotocol/server-filesystem without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | github | github runs ghcr.io/github/github-mcp-server without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | fetch | fetch runs mcp-server-fetch without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | terminal | terminal runs @wonderwhy-er/desktop-commander without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-12 | medium | internal-crm | internal-crm (python /opt/tools/crm_server.py --api-key=***REDACTED***) is not in the capability catalog, so its access cannot be assessed. | Document what the tool can read, write and send, and add it to catalog.yaml. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="vscode-mcp"></a>
## MCP host (vscode-mcp.json)

- **ID:** `vscode-mcp` (mcp-config)
- **Source:** `examples/vscode-mcp.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/vscode-mcp.json` (sha256 `a0bfa988e24624cc…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| github | github | `https://api.githubcopilot.com/mcp/` | read, write | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| jira | unknown | `http://mcp.tools.example.com/jira` | unknown | internal |  |  | **Investigate** | ☐ Keep ☐ Modify ☐ Revoke |
| git | git | `${workspaceFolder}` | read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | github | github can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | git | git can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (git, github), ingests untrusted content (github) and can send data out (github) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-11 | high | jira | jira connects to http://mcp.tools.example.com/jira over unencrypted HTTP. | Use HTTPS so credentials and tool traffic are encrypted in transit. |
| AAR-12 | medium | jira | jira (http://mcp.tools.example.com/jira) is not in the capability catalog, so its access cannot be assessed. | Document what the tool can read, write and send, and add it to catalog.yaml. |
| AAR-14 | medium | git | git runs mcp-server-git 2025.7.1, which has 4 known vulnerabilities (CVE-2025-68143, CVE-2025-68144, CVE-2025-68145, CVE-2026-27735). | Upgrade to 2026.1.14 or later and pin it. |
| AAR-07 | low | github | No rotation date is recorded for github.header.Authorization. | Record when the credential was issued so rotation can be evidenced. |
| AAR-07 | low | jira | No rotation date is recorded for jira.header.Authorization. | Record when the credential was issued so rotation can be evidenced. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |
