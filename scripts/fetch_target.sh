#!/usr/bin/env bash
# Clone the real upstream target at the vulnerable commit (sparse + shallow + blobless: a few MB,
# not the multi-GB langchain monorepo). Third-party code: lands in targets/upstream/ (gitignored).
#
#   ce61840e (2023-09-18) is vulnerable to both CVEs and still importable:
#     - CVE-2024-21513: vector_sql._try_eval eval()s DB values (fixed in 7b13292e, 2023-09-23)
#     - CVE-2023-44467: PALChain denylist lacks __import__   (fixed in 4c97a10b, 2023-09-29)
#   The next vector_sql commit (12ff7800) switched to `from langchain.schema.base import Embeddings`,
#   a module no langchain release ever shipped, so from then until the fix (incl. the 0.0.20 wheel)
#   the vulnerable module could not even be imported. Runtime: langchain==0.0.292 (.venv-target; 0.0.293 already dropped langchain.embeddings.base).
# Usage: scripts/fetch_target.sh [commit]
set -euo pipefail
cd "$(dirname "$0")/.."
COMMIT=${1:-ce61840e3b25d48a2f5088b0887efc4e6f903439}
DEST=targets/upstream/langchain
if [[ -d $DEST/.git ]] && [[ $(git -C "$DEST" rev-parse HEAD 2>/dev/null) == "$COMMIT" ]]; then
  echo "$DEST already at $COMMIT"; exit 0
fi
rm -rf "$DEST"; mkdir -p "$DEST"
git -C "$DEST" init -q
git -C "$DEST" remote add origin https://github.com/langchain-ai/langchain
git -C "$DEST" sparse-checkout set --no-cone /libs/experimental/langchain_experimental/ \
  /libs/experimental/tests/unit_tests/ /libs/experimental/pyproject.toml
git -C "$DEST" fetch -q --depth 1 --filter=blob:none origin "$COMMIT"
git -C "$DEST" -c advice.detachedHead=false checkout -q FETCH_HEAD
echo "$DEST @ $(git -C "$DEST" rev-parse --short HEAD) · $(du -sh --exclude=.git "$DEST" | cut -f1) checked out"
