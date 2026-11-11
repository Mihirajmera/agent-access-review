# Changelog

## 0.3.0 (2026-11-11)

- New check `AAR-13`: an agent that runs a deprecated or archived MCP server is reported as high, with the maintained replacement when there is one. Most of the original reference servers (GitHub, Postgres, Slack, Puppeteer, Brave Search, Google Drive, Redis, Google Maps, GitLab, AWS KB Retrieval, EverArt) were archived in 2025 and their npm packages deprecated, but they still appear in many READMEs and configs. They no longer receive security fixes. The catalog now also classifies `redis`, `google-maps`, `gitlab`, `aws-kb-retrieval`, `everart` and the maintained Brave, Redis and Bedrock KB servers (#29).
- VS Code `mcp.json` files with comments and trailing commas (JSONC) are now reviewed instead of skipped; malformed input is still rejected (#12, thanks @premsinghsodha7).
- `scan --format json` prints each agent's findings as one JSON document on stdout for CI and other tools; the review packet and `--fail-on` exit codes are unchanged (#19, thanks @CJstate).
- The `mcp-server-sqlite`, Brave Search and Google Drive MCP servers are now classified instead of reported as unknown (#20, thanks @CJstate).
- Fixed: a secret passed as `--token value` (space separated, which is how most CLIs document it) is now reported as a hardcoded credential and redacted. Only `--token=value` was recognised, so the spaced form reached `evidence/<agent>.json` verbatim.
- Fixed: configs saved with a UTF-8 byte-order mark are now read. Notepad and PowerShell's `Out-File` write one by default on Windows, and the BOM made the file unreadable, which `discover()` reported as skipped: the host silently disappeared from the review.
- Fixed: two hosts configured in different folders no longer share one agent id. `evidence/<id>.json` was written twice, so the second overwrote the first and the OSCAL results kept only one observation.
- Fixed: a credential embedded in a remote server's URL — a `?api_key=...` style query parameter or a password in the userinfo — is now reported as a hardcoded credential (AAR-06) and masked in the report, the spreadsheet and the evidence. A remote server is configured by URL alone, so that URL was the one place a token could sit unseen: it reached `access-review.md`, `access-review.csv` and `evidence/<agent>.json` verbatim.
- Fixed: the decision sheet no longer lets a value from the scanned config be read as a spreadsheet formula. `access-review.csv` is opened in Excel, LibreOffice or Sheets, and every cell in it comes from a config this tool did not write — an MCP server named `=cmd|'/c calc'!A1` was evaluated on open. Cells that start with `=`, `+`, `-`, `@`, tab or CR now carry the spreadsheet text marker. A bare CR in a value also no longer ends a Markdown table row early, which used to push the rest of that row's cells outside the table.
- Fixed: `AAR-11` read the endpoint host with a regex, which took the userinfo for the host — `http://127.0.0.1:80@evil.example.com/sse` was exempted as loopback while it actually connects to `evil.example.com`. The host now comes from `urlsplit`. The same change stops `http://[::1]:8080/sse`, `http://LOCALHOST./sse` and `http://127.0.0.2/sse` from being reported as unencrypted remote traffic when they never leave the machine.
- Fixed: an agent manifest is now read whatever its extension. A manifest saved as `agents.json` was ignored entirely — the JSON branch only looked for `mcpServers`, so the scan reported "No MCP configs or agent manifests found" and the agents it described never appeared in the review.
- Fixed: a manifest may now write `approved_on`, `last_used` and `last_rotated` with a time. YAML parses an unquoted `2026-10-12 09:00:00` into a `datetime`, which is a subclass of `date`, so it passed the type check and then aborted the whole scan with `TypeError: unsupported operand type(s) for -: 'datetime.date' and 'datetime.datetime'` inside `AAR-02`. Timestamps are reduced to their day.
- Fixed: `actions` and `scopes` now accept a single value as well as a list. `actions: delete` was read as a string and split into `{'d','e','l','t','e'}`, none of which is a privileged action, so `AAR-03` stayed silent on a grant that can delete; `scopes: repo` became `{'r','e','p','o'}`, which matches no broad scope, so `AAR-04` stayed silent on full repository access. The same shape reached the review, which listed one scope per letter.
- Fixed: `untrusted_input`, `egress`, `requires_approval` and `sandboxed` now read a quoted boolean as a boolean. `bool('false')` is `True`, so `sandboxed: "false"` read as "sandboxed" and `AAR-05` passed a tool that runs commands on the host; `requires_approval: "false"` read as "needs approval" and `AAR-03` passed a delete grant. An unrecognised value falls back to the answer that does not silence a check.

## 0.2.1 (2026-10-19)

- **Case study:** scanned the configuration examples from 9 official MCP server READMEs ([case-studies/official-mcp-readmes](case-studies/official-mcp-readmes)).
- Catalog entries can list `aliases`; the official Docker images (`mcp/filesystem`, `mcp/postgres`, `mcp/puppeteer`, `mcp/memory`, `mcp/fetch`, `mcp/git`) and the `mcp-server-git` uvx package are now classified instead of reported as unknown.
- Docker and Podman bind mounts (`-v`, `--mount`) become the grant's scopes, so mounting a home directory is caught by AAR-04; grants whose mounts are all read-only are treated as read-only.
- Fixed: a malformed config file no longer aborts the scan (found by fuzzing).

## 0.2.0 (2026-10-17)

- `agent-access-review demo` reviews the bundled examples right after `pip install`; no clone needed.
- Committed [`sample-output/`](sample-output) so the report can be read without running anything; CI checks it stays current.
- Reproducible output: set `SOURCE_DATE_EPOCH` for byte-identical evidence and OSCAL (deterministic OSCAL UUIDs, LF line endings on every OS).
- Sources inside a scanned folder are recorded relative to it, so evidence hashes don't depend on the install path.
- OpenSSF Scorecard workflow, contributing guide and issue forms.

## 0.1.0 (2026-10-16)

First release: 12 access-review checks for AI agents and MCP servers, reviewer packet, decision sheet, hashed evidence and OSCAL output.
