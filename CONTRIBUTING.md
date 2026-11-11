# Contributing

Thanks for helping. The most useful contributions are small and concrete.

## Add an MCP server to the capability catalog

Unknown servers are flagged (AAR-12) until someone documents what they can do. To add one, either open a **Catalog entry** issue, or edit [`agent_access_review/catalog.yaml`](agent_access_review/catalog.yaml) directly:

```yaml
"@scope/server-name":            # package name exactly as it appears in MCP configs
  tool: short-category            # filesystem, shell, email, ...
  actions: [read, write]          # read | write | delete | send | execute | admin
  data_classification: confidential
  untrusted_input: true           # returns content an outsider can write (web, email, tickets)
  egress: true                    # can send data outside the organization
```

Please link the server's documentation in the pull request so the classification can be checked.

## Report a wrong finding

If a check flags something that's actually fine, or misses something risky, open a **Bug report** with a config that reproduces it. Remove real tokens and passwords first.

## Code changes

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -q
```

- Every new check needs tests for the passing and failing case, and an entry in `controls.yaml` with its framework mappings.
- To refresh the vulnerability data AAR-14 uses, run `python scripts/update_advisories.py` and commit `agent_access_review/advisories.yaml` together with the regenerated sample.
- If your change alters the report, regenerate the sample: `SOURCE_DATE_EPOCH=1791763200 python -m agent_access_review demo --out sample-output`. CI fails if `sample-output/` is stale.
- Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
