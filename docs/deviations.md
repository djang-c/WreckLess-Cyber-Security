# Deviations: changes to what counts as a pass

Every change to a gating check, threshold or fixture is logged here with its date and reason.

## 2026-10-25: functional suite accepts the upstream fix design (CVE-2024-21513)

**Change.** Two tests in `targets/victim_app/tests/test_functional.py` changed:
- `test_embeddings_round_trip_as_lists` became `..._or_raw`.
- `test_literal_strings_become_python_values` became `test_literal_strings_become_values_or_stay_raw`.

Both now accept either design:
- (a) values that look like Python literals are parsed by a literal-only parser into the exact value and type;
- (b) they are returned unchanged.

Each row must use one design throughout, never a mix of the two. Nothing else is accepted.

**Reason.** The stricter version, from `f855e0f` the same day, accepted only design (a). Upstream fix `7b13292e` (PR #10937) deletes `_try_eval` and returns raw values, which is design (b). The stricter tests therefore rejected the maintainer's own fix: 2 of 8 functional tests failed when we ran it. Blue's first live `qwen3:8b` attempt tried exactly that fix.

**Evidence** (`tests/test_blue_proof.py`):

| Patch | Result |
|---|---|
| upstream-style fix (`tests/fixtures/bypass/cve-2024-21513_upstream_style.patch`) | passes every check (`test_upstream_style_fix_passes_all_checks`) |
| reference `ast.literal_eval` fix | still passes |
| `str(x)` cast | still fails functional (`test_native_values_pass_through`) |
| denylist and conftest bypasses | still fail |

**Known cost.** A patch that breaks parsing by accident now passes, as long as it then behaves exactly like upstream. One example is Blue's live `json.loads` patch without `import json`: it raises `NameError`, the `except` swallows it, and every value comes back raw. Such a patch is behaviourally equal to the upstream fix but would fail code review. Catching it is the job of the human approval step ("Fix branch ready (local, pending review)").

**Decided by:** the team (Person B), 2026-10-25.
