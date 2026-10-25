#!/usr/bin/env bash
# Pull every model in scripts/models.tsv into ./models at its pinned revision.
# Exits non-zero (and says which) if any download failed; re-running resumes.
# Needs the `hf` CLI: pip install -e '.[models]'
set -euo pipefail
cd "$(dirname "$0")/.."
export HF_XET_HIGH_PERFORMANCE=1
HF=${HF:-.venv/bin/hf}
failed=()
while read -r role port names util parser repo rev _extra; do
  [[ -z $role || $role == \#* ]] && continue
  echo "[$(date +%T)] >>> $repo @ $rev"
  if ! "$HF" download "$repo" --revision "$rev" --local-dir "models/${repo#*/}"; then
    echo "FAILED $repo"; failed+=("$repo")
  fi
done < scripts/models.tsv
if (( ${#failed[@]} )); then
  echo "[$(date +%T)] ${#failed[@]} FAILED: ${failed[*]}"; exit 1
fi
echo "[$(date +%T)] ALL DONE"
