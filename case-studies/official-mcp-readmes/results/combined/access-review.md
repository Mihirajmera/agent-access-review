# AI Agent Access Review: 2026-10-19

**1 agents**, **9 tool grants**, **21 findings** (10 high, 10 medium, 1 low).

## Agents

| Agent | Source | Owner | Approved | Tools | High | Medium | Low |
|---|---|---|---|---:|---:|---:|---:|
| [MCP host (claude_desktop_config.json)](#claude-desktop-config) | `claude_desktop_config.json` | **none** | **none** | 9 | 10 | 10 | 1 |

## Control results

| Check | Control | Agents failing | Frameworks |
|---|---|---:|---|
| AAR-01 | Every agent has an accountable human owner | 1 / 1 | NIST 800-53 AC-2; SOC 2 CC6.2; NIST AI RMF GOVERN 2.1 |
| AAR-02 | Agent access is approved and recertified within 90 days | 1 / 1 | NIST 800-53 AC-2; SOC 2 CC6.2, CC6.3 |
| AAR-03 | Privileged agent actions require human approval | 1 / 1 | NIST 800-53 AC-6; SOC 2 CC6.3; NIST AI RMF MAP 3.5; OWASP LLM LLM06 |
| AAR-04 | Tool scopes follow least privilege | 0 / 1 | NIST 800-53 AC-6; SOC 2 CC6.3; OWASP LLM LLM06 |
| AAR-05 | Code and shell execution is sandboxed | 1 / 1 | NIST 800-53 CM-7, AC-6; OWASP LLM LLM05, LLM06 |
| AAR-06 | No credentials are hardcoded in agent configuration | 1 / 1 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-07 | Agent credentials are rotated within 90 days | 0 / 1 | NIST 800-53 IA-5; SOC 2 CC6.1 |
| AAR-08 | Dormant agent access is removed after 90 days | 1 / 1 | NIST 800-53 AC-2(3); SOC 2 CC6.2 |
| AAR-09 | No unmitigated data exfiltration path | 1 / 1 | NIST 800-53 AC-4; NIST AI RMF MEASURE 2.7; OWASP LLM LLM01, LLM02 |
| AAR-10 | Tool packages are pinned to a version | 1 / 1 | NIST 800-53 SR-3; OWASP LLM LLM03 |
| AAR-11 | Remote tools use encrypted transport | 0 / 1 | NIST 800-53 SC-8; SOC 2 CC6.7 |
| AAR-12 | Every tool's capabilities are inventoried | 0 / 1 | NIST 800-53 CM-8; NIST AI RMF GOVERN 1.6 |

---

<a id="claude-desktop-config"></a>
## MCP host (claude_desktop_config.json)

- **ID:** `claude-desktop-config` (mcp-config)
- **Source:** `combined/claude_desktop_config.json`
- **Owner:** none recorded
- **Approval:** none recorded
- **Evidence:** `evidence/claude-desktop-config.json` (sha256 `d049e5e54b158365…`)

### Access inventory

| Tool | Type | Resource | Actions | Data | Untrusted input | Egress | Recommended | Reviewer decision |
|---|---|---|---|---|:---:|:---:|---|---|
| desktop-commander | shell | `@wonderwhy-er/desktop-commander` | delete, execute, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| fetch | fetch | `mcp-server-fetch` | read | public | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| filesystem | filesystem | `/Users/username/Desktop, /path/to/other/allowed/dir (read-only), /path/to/file.txt` | delete, read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| git | git | `path/to/git/repo` | read, write | confidential |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| memory | memory | `mcp/memory` | read, write | internal |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| postgres | postgres | `postgresql://host.docker.internal:5432/mydb` | read | restricted |  |  | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| puppeteer | browser | `mcp/puppeteer` | read, send | public | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| slack | slack | `@modelcontextprotocol/server-slack` | read, send | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |
| github | github | `https://api.githubcopilot.com/mcp/` | read, write | confidential | yes | yes | **Modify** | ☐ Keep ☐ Modify ☐ Revoke |

### Findings

| Check | Severity | Tool | Finding | Recommendation |
|---|---|---|---|---|
| AAR-01 | high | (agent) | No accountable human owner is recorded for this agent. | Assign an owner who answers for what the agent does, or decommission it. |
| AAR-02 | high | (agent) | Agent access has no recorded approval. | Route the agent through access approval before its next use. |
| AAR-03 | high | desktop-commander | desktop-commander can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | filesystem | filesystem can delete / write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | git | git can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | slack | slack can send confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | high | github | github can write confidential data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-05 | high | desktop-commander | desktop-commander can execute arbitrary commands on the host without a sandbox. | Run the tool in a container or VM with no host credentials mounted, or remove it. |
| AAR-06 | high | slack | Credential slack.SLACK_BOT_TOKEN is stored in plain text in the agent configuration. | Revoke and reissue it, then load it from a secret manager or environment reference. |
| AAR-09 | high | (agent) | Exfiltration path: reads sensitive data (desktop-commander, filesystem, git, github, postgres, slack), ingests untrusted content (fetch, github, puppeteer, slack) and can send data out (fetch, github, puppeteer, slack) with no human approval. A prompt injection in the untrusted content could leak the data. | Break the chain: split the agent, remove one leg, or require approval on every egress action. |
| AAR-03 | medium | memory | memory can write internal data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-03 | medium | puppeteer | puppeteer can send public data without a human approving each action. | Require human confirmation for these actions, or reduce the tool to read-only. |
| AAR-10 | medium | desktop-commander | desktop-commander runs @wonderwhy-er/desktop-commander without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | fetch | fetch runs mcp-server-fetch without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | filesystem | filesystem runs mcp/filesystem without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | git | git runs mcp-server-git without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | memory | memory runs mcp/memory without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | postgres | postgres runs mcp/postgres without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | puppeteer | puppeteer runs mcp/puppeteer without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-10 | medium | slack | slack runs @modelcontextprotocol/server-slack without a pinned version, so a new upstream release runs automatically. | Pin an exact version (npm/PyPI) or image digest and update it through change control. |
| AAR-08 | low | (agent) | No tool usage is logged, so dormant access cannot be identified. | Log tool calls per agent so unused access can be found and removed. |

### Sign-off

I have reviewed each tool grant above and confirm the decisions recorded.

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |
