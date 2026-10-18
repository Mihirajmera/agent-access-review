#!/bin/bash -eu
# Runtime dependencies, pinned by version and hash.
pip3 install --require-hashes -r .clusterfuzzlite/requirements.txt

# Bundle every fuzz target with the package (and any data files it loads at import time).
for fuzzer in $(find "$SRC/agent-access-review/fuzz" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/agent-access-review" \
    --add-data "agent_access_review/catalog.yaml:agent_access_review" \
    --add-data "agent_access_review/controls.yaml:agent_access_review"
done
