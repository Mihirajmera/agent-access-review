# AI Agent Access Review: 2026-10-19

**9 agents**, **9 tool grants**, **46 findings** (27 high, 10 medium, 9 low).

## Agents

| Agent | Source | Owner | Approved | Tools | High | Medium | Low |
|---|---|---|---|---:|---:|---:|---:|
| [MCP host (desktop-commander.json)](#desktop-commander) | `desktop-commander.json` | **none** | **none** | 1 | 4 | 1 | 1 |
| [MCP host (fetch.json)](#fetch) | `fetch.json` | **none** | **none** | 1 | 2 | 1 | 1 |
| [MCP host (filesystem.json)](#filesystem) | `filesystem.json` | **none** | **none** | 1 | 3 | 1 | 1 |
| [MCP host (git.json)](#git) | `git.json` | **none** | **none** | 1 | 3 | 1 | 1 |
| [MCP host (memory.json)](#memory) | `memory.json` | **none** | **none** | 1 | 2 | 2 | 1 |
| [MCP host (postgres.json)](#postgres) | `postgres.json` | **none** | **none** | 1 | 2 | 1 | 1 |
| [MCP host (puppeteer.json)](#puppeteer) | `puppeteer.json` | **none** | **none** | 1 | 2 | 2 | 1 |
| [MCP host (slack.json)](#slack) | `slack.json` | **none** | **none** | 1 | 5 | 1 | 1 |
| [MCP host (vscode-github.json)](#vscode-github) | `vscode-github.json` | **none** | **none** | 1 | 4 | 0 | 1 |

## Control results

| Check | Control | Agents failing | Frameworks |
|---|---|---:|---|
| AAR-01 | Every agent has an accountable human owner | 9 / 9 | NIST 800-53 AC-2; SOC 2 CC6.2; NIST AI RMF GOVERN 2.1 |
| AAR-02 | Agent access is approved and recertified within 90 days | 9 / 9 | NIST 800-53 AC-2; SOC 2 CC6.2, CC6.3 |
| AAR-03 | Privileged agent actions require human approval | 7 / 9 | NIST 800-53 AC-6; SOC 2 CC6.3; NIST AI RMF MAP 3.5; OWASP LLM LLM06 |
| AAR-04 | Tool scopes follow least privilege | 0 / 9 | NIST 800-53 AC-6; SOC 2 CC6.3; OWASP LLM LLM06 |
| AAR-05 | Code and shell execution is sandboxed | 1 / 9 | NIST 800-53 CM-7, AC-6; OWASP LLM LLM05, LLM06 |
| AAR-06 | No credentials are hardcoded in agent configuration | 1 / 9 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-07 | Agent credentials are rotated within 90 days | 0 / 9 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-08 | Dormant agent access is removed after 90 days | 9 / 9 | NIST 800-53 AC-2(3); SOC 2 CC6.2 |
| AAR-09 | No unmitigated data exfiltration path | 2 / 9 | NIST 800-53 AC-4; NIST AI RMF MEASURE 2.7; OWASP LLM LLM01, LLM02 |
| AAR-10 | Tool packages are pinned to a version | 8 / 9 | NIST 800-53 SR-3; OWASP LLM LLM03 |
| AAR-11 | Remote tools use encrypted transport | 0 / 9 | NIST 800-53 SC-8; SOC 2 CC6.7 |
| AAR-12 | Every tool's capabilities are inventoried | 0 / 9 | NIST 800-53 CM-8; NIST AI RMF GOVERN 1.6 |

---

<a id="desktop-commander"></a>
## MCP host (desktop-commander.json)

- **ID:** `desktop-commander` (mcp-config)
- **Source:** `configs/desktop-commander.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/desktop-commander.json` (sha256 `88ef7e6862613cd0…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| desktop-commander | shell | `@wonderwhy-er/desktop-commander` | delete, execute, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | desktop-commander | desktop-commander can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-05 | high | desktop-commander | desktop-commander can execute arbitrary commands on the host without a sandbox. | Run the tool in a container or VM with no host credentials mounted, or remove it. |
| AAR-10 | medium | desktop-commander | desktop-commander runs @wonderwhy-er/desktop-commander without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="fetch"></a>
## MCP host (fetch.json)

- **ID:** `fetch` (mcp-config)
- **Source:** `configs/fetch.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/fetch.json` (sha256 `13225ff84283cf92…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| fetch | fetch | `mcp-server-fetch` | read | public | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-10 | medium | fetch | fetch runs mcp-server-fetch without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="filesystem"></a>
## MCP host (filesystem.json)

- **ID:** `filesystem` (mcp-config)
- **Source:** `configs/filesystem.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/filesystem.json` (sha256 `b50d3bc183985f47…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| filesystem | filesystem | `/Users/username/Desktop, /path/to/other/allowed/dir (read-only), /path/to/file.txt` | delete, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | filesystem | filesystem can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-10 | medium | filesystem | filesystem runs mcp/filesystem without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="git"></a>
## MCP host (git.json)

- **ID:** `git` (mcp-config)
- **Source:** `configs/git.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/git.json` (sha256 `fd5b533504c6909b…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| git | git | `path/to/git/repo` | read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | git | git can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-10 | medium | git | git runs mcp-server-git without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="memory"></a>
## MCP host (memory.json)

- **ID:** `memory` (mcp-config)
- **Source:** `configs/memory.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/memory.json` (sha256 `969951917036ffd5…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| memory | memory | `mcp/memory` | read, write | internal |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | medium | memory | memory can write internal data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-10 | medium | memory | memory runs mcp/memory without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="postgres"></a>
## MCP host (postgres.json)

- **ID:** `postgres` (mcp-config)
- **Source:** `configs/postgres.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/postgres.json` (sha256 `a9cd50103c4e2588…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| postgres | postgres | `postgresql://host.docker.internal:5432/mydb` | read | restricted |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-10 | medium | postgres | postgres runs mcp/postgres without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="puppeteer"></a>
## MCP host (puppeteer.json)

- **ID:** `puppeteer` (mcp-config)
- **Source:** `configs/puppeteer.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/puppeteer.json` (sha256 `f0575ce065ed0f28…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| puppeteer | browser | `mcp/puppeteer` | read, send | public | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | medium | puppeteer | puppeteer can send public data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-10 | medium | puppeteer | puppeteer runs mcp/puppeteer without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="slack"></a>
## MCP host (slack.json)

- **ID:** `slack` (mcp-config)
- **Source:** `configs/slack.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/slack.json` (sha256 `b924d24ddcbf49b4…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| slack | slack | `@modelcontextprotocol/server-slack` | read, send | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | slack | slack can send confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-06 | high | slack | Credential slack.SLACK_BOT_TOKEN is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (slack), ingests untrusted content (slack) and can send data out (slack) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-10 | medium | slack | slack runs @modelcontextprotocol/server-slack without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |

---

<a id="vscode-github"></a>
## MCP host (vscode-github.json)

- **ID:** `vscode-github` (mcp-config)
- **Source:** `configs/vscode-github.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/vscode-github.json` (sha256 `95ed0adb8f3e748c…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| github | github | `https://api.githubcopilot.com/mcp/` | read, write | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | github | github can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (github), ingests untrusted content (github) and can send data out (github) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |
