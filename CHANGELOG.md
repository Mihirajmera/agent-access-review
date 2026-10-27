# Changelog

## Unreleased

- VS Code `mcp.json` files with comments and trailing commas (JSONC) are now reviewed instead of skipped; malformed input is still rejected (#12, thanks @premsinghsodha7).
- `scan --format json` prints each agent's findings as one JSON document on stdout for CI and other tools; the review packet and `--fail-on` exit codes are unchanged (#19, thanks @CJstate).
- The `mcp-server-sqlite`, Brave Search and Google Drive MCP servers are now classified instead of reported as unknown (#20, thanks @CJstate).
- Fixed: an agent manifest is now read whatever its extension. A manifest saved as `agents.json` was ignored entirely — the JSON branch only looked for `mcpServers`, so the scan reported "No MCP configs or agent manifests found" and the agents it described never appeared in the review.
- Fixed: a manifest may now write `approved_on`, `last_used` and `last_rotated` with a time. YAML parses an unquoted `2026-10-12 09:00:00` into a `datetime`, which is a subclass of `date`, so it passed the type check and then aborted the whole scan with `TypeError: unsupported operand type(s) for -: 'datetime.date' and 'datetime.datetime'` inside `AAR-02`. Timestamps are reduced to their day.

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
