# 2,830 public MCP configs, reviewed

What do AI agents run with, when developers commit their MCP client configs to public GitHub repos?
This folder holds the method and the aggregate results. Write-up:
[mihirajmera.github.io/case-studies/public-mcp-configs](https://mihirajmera.github.io/case-studies/public-mcp-configs/).

## Method

1. **Collect** (`collect.py`): GitHub code search, up to 1,000 results per client (the API's limit):

   | Client | Query |
   |---|---|
   | Claude Desktop | `filename:claude_desktop_config.json mcpServers` |
   | Claude Code | `filename:.mcp.json mcpServers` |
   | VS Code | `path:.vscode filename:mcp.json servers` |
   | Cursor | `path:.cursor filename:mcp.json mcpServers` |

   Each file is fetched at the commit the search indexed and stored by content hash, so forks and
   templates copied verbatim count once. Run on 2026-11-11: 3,250 files, 2,890 unique.
2. **Review** (`analyze.py`): every unique config through agent-access-review (main at 2026-11-11,
   with #35). Only checks a bare config can answer are counted: AAR-04, 05, 06, 09, 10, 11, 13, 14.
   Owner, approval and rotation checks need an agent manifest, so they're left out.
3. **Credentials** (`secrets.py`): credential-named `env` and header values are classified as
   placeholder, real-looking, or a known provider key format. It prints counts only. No value was
   printed, stored outside the local copy, or tested against any service.

`results.txt` is the output of steps 2 and 3.

## Limits

- Code search ranks by relevance and stops at 1,000 per query, so this is a large sample, not a
  census, and not random.
- Public repos skew toward templates, demos and tutorials. Private, production configs may differ.
- AAR-14 needs an exact version. Unpinned servers resolve to whatever is newest when they start,
  so they're counted under AAR-10, not AAR-14.

## Privacy

No repository names, paths or file contents are published here: only totals. Anyone can
reproduce the run with the scripts.
