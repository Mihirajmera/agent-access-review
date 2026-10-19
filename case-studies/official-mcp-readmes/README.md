# Case study: the MCP configs that official READMEs tell you to copy

**Question:** if a developer sets up MCP servers by copying the configuration examples from the servers' own READMEs, what access does their AI agent end up with?

**Method:** I took the **first valid configuration example** from 9 widely used MCP server READMEs (official reference servers, GitHub's MCP server and a popular community server), saved each exactly as published, and scanned them with agent-access-review on 2026-10-19. Every config links to the exact line and commit it came from: see [`sources.json`](sources.json). Nothing was modified except combining them in one scenario below.

> These are documentation examples, written to be easy to copy, not production setups. The point isn't that the READMEs are wrong; it's that **copy-pasting them without a review produces the access below**, and nothing in a typical workflow flags it.

## Results, one config at a time

| Server (README line) | Capability | Actions | Findings |
|---|---|---|---|
| [desktop-commander](https://github.com/wonderwhy-er/DesktopCommanderMCP/blob/2f4327e0f17c/README.md#L154) | shell | read, write, delete, **execute** | AAR-03, **AAR-05**, AAR-10 |
| [filesystem](https://github.com/modelcontextprotocol/servers/blob/51b6382a3e82/src/filesystem/README.md#L238) | filesystem | read, write, delete | AAR-03, AAR-10 |
| [git](https://github.com/modelcontextprotocol/servers/blob/51b6382a3e82/src/git/README.md#L147) | git | read, write | AAR-03, AAR-10 |
| [memory](https://github.com/modelcontextprotocol/servers/blob/51b6382a3e82/src/memory/README.md#L158) | memory | read, write | AAR-03, AAR-10 |
| [puppeteer](https://github.com/modelcontextprotocol/servers-archived/blob/9be4674d1ddf/src/puppeteer/README.md#L91) | browser | read, send | AAR-03, AAR-10 |
| [slack](https://github.com/modelcontextprotocol/servers-archived/blob/9be4674d1ddf/src/slack/README.md#L96) | slack | read, send | AAR-03, **AAR-06**, AAR-10 |
| [fetch](https://github.com/modelcontextprotocol/servers/blob/51b6382a3e82/src/fetch/README.md#L79) | fetch | read | AAR-10 |
| [postgres](https://github.com/modelcontextprotocol/servers-archived/blob/9be4674d1ddf/src/postgres/README.md#L35) | postgres | read | AAR-10 |
| [github (VS Code, remote)](https://github.com/github/github-mcp-server/blob/e3809fe91c75/README.md#L55) | github | read, write | AAR-03 |

Full output: [per-config review packet](results/per-config/access-review.md) · [decision sheet](results/per-config/access-review.csv).

**What stands out**

- **8 of 9 run an unpinned package or image (AAR-10).** `npx -y <package>`, `@latest`, `uvx <package>` and untagged `docker run mcp/...` all fetch whatever was published most recently, every time the client starts. A compromised release would run with the agent's access, without any change to your config.
- **7 of 9 grant write, send, delete or execute (AAR-03).** That's the purpose of most of these servers, so the finding is about *governance*: who approved giving an agent that power, and is there a human check on each action?
- **The Slack example tells you to paste the bot token into the config (AAR-06).** Its `env` block sets `SLACK_BOT_TOKEN` to `xoxb-your-bot-token`, a placeholder you replace with the real token, so following it leaves the token as plain text in a JSON file on disk and in any backup or dotfiles repo, rather than referenced from a secret store.
- **Desktop Commander gives the agent an unsandboxed shell (AAR-05)** on the host, with your user's permissions.

## Results when they're combined

Developers rarely run one server. Following several READMEs and pasting every snippet into one `claude_desktop_config.json` ([combined config](combined/claude_desktop_config.json)) produces one agent with all nine servers:

> **AAR-09 (high): exfiltration path.** The agent reads sensitive data (desktop-commander, filesystem, git, github, postgres, slack), ingests content outsiders can write (fetch, github, puppeteer, slack) and can send data out (fetch, github, puppeteer, slack) with no human approval. A prompt injection in a web page, issue or Slack message could make it leak that data.

No single README creates this risk. **The combination does**, which is exactly what per-server documentation and per-tool reviews miss. Full output: [combined review packet](results/combined/access-review.md).

## What this taught me about my own tool

Scanning real configs found two gaps in agent-access-review, both fixed in this change:

1. **5 of the 9 configs were initially "unclassified" (AAR-12).** The capability catalog only knew npm package names, but the official READMEs now mostly recommend **Docker images** (`mcp/filesystem`, `mcp/postgres`, `mcp/puppeteer`, `mcp/memory`) or **uvx** (`mcp-server-git`). The catalog now supports `aliases`, and all 9 are assessed.
2. **Docker mounts were invisible.** For containerized servers, what the agent can reach is set by `-v` / `--mount` flags, not the server's arguments. The scanner now reads host bind mounts as the grant's scopes (so `--mount src=/Users/you` is judged as home-directory access) and downgrades the grant to read-only when every mount is `ro`.

## Caveats

- **Client-side approval isn't visible in config files.** Some MCP clients ask before each tool call or let you allow tools per session. The scanner can't see that setting, so AAR-03 reports what the *configuration* allows. Teams that rely on client prompts can record `requires_approval: true` in an [`agents.yaml`](../../agent_access_review/examples/agents.yaml) manifest.
- **Placeholders.** Values in angle brackets like `<YOUR_TOKEN>` are treated as references, not secrets. The Slack example's `xoxb-your-bot-token` is a placeholder too, but it sits where the real token goes as a literal string, so it's flagged for the pattern it teaches.
- **The archived servers** (postgres, puppeteer, slack) have moved to `servers-archived`, but their READMEs are still widely linked and copied.
- Mappings to NIST 800-53, SOC 2, NIST AI RMF and OWASP LLM Top 10 are my own judgment; see [`controls.yaml`](../../agent_access_review/controls.yaml).

## Reproduce

```bash
pip install "git+https://github.com/Mihirajmera/agent-access-review"
agent-access-review scan case-studies/official-mcp-readmes/configs --as-of 2026-10-19
agent-access-review scan case-studies/official-mcp-readmes/combined --as-of 2026-10-19
```
