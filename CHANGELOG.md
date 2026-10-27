# Changelog

## Unreleased

- VS Code `mcp.json` files with comments and trailing commas (JSONC) are now reviewed instead of skipped; malformed input is still rejected (#12, thanks @premsinghsodha7).
- `scan --format json` prints each agent's findings as one JSON document on stdout for CI and other tools; the review packet and `--fail-on` exit codes are unchanged (#19, thanks @CJstate).
- The `mcp-server-sqlite`, Brave Search and Google Drive MCP servers are now classified instead of reported as unknown (#20, thanks @CJstate).
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
