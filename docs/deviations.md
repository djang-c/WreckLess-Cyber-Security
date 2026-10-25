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


## 2026-10-25: gate verdicts gain a strength; a Red-hunt pass is REACHABLE, not VERIFIED

**Change.** `gate.verify` (`wreckless/gate.py`) now returns `passed` plus a `strength`.

`verified` requires all three:
- a reference-patched control;
- the oracle write coming from the same innermost victim function as the reference exploit;
- the existing checks.

`reachable` covers everything else that passes: a null-victim control, or no reference exploit. Such items are labelled `REACHABLE` in the queue and the intrusion banner says "flaw unconfirmed". They still go to Blue.

**Reason.** An independent skeptical review on 2026-10-25 got three scripts that never use either flaw VERIFIED, with and without a reference fix (`tests/fixtures/gate_bypass/a1`–`a4`):
- **a1:** imported the guard module, switched its hook off and forged provenance.
- **a2/a3:** a harmless victim callback, which a3 combined with recognising the control by its source text.
- **a4:** rewrote the guard file, which persisted into later runs.

All four are now rejected and kept as regression tests. On top of the strength rule:
- guard state is hidden in a closure;
- the guard file is rewritten before every run;
- copies are look-alike, in random order;
- tokens are independent.

**Known residual.** A white-box forgery that digs the guard's state out of `gc` (`a8_gc_dig_forge.py`) is still VERIFIED. It is recorded as a strict-xfail test and stated in the README. Fixing it needs out-of-process provenance.

**Update 2026-10-25 (Kevin, `84e293a`).** gc introspection is now a guard violation and any violation rejects the run, so `a8_gc_dig_forge.py` is rejected; the strict xfail became `test_gc_dig_forgery_is_rejected`. Remaining residual: a payload that leaves Python (`os.system`) is outside the in-process hook; the control run is the backstop.

**Decided by:** the team (Person B), 2026-10-25.

## 2026-10-25: second oracle kind, the leak oracle (CVE-2024-23334)

**Change.** `wreckless/sandbox.py` and `wreckless/gate.py` gain a second oracle kind for read bugs. A script whose first 2 KB contain `# wreckless-oracle: leak` runs in leak mode; every other script runs exactly as before (nonce mode, unchanged code path and tests).

In leak mode:
- the host plants a fresh secret in a file outside the victim tree and outside `tmp/`, passes its path as `WRECKLESS_SECRET_FILE`, and sets no `WRECKLESS_NONCE`;
- the script must get the secret from the victim and write it to the oracle file; the oracle now holds the secret instead of the nonce, and the script (not victim code) writes it;
- the guard raises a violation (run rejected) if payload code reads the secret file itself, and records the victim function that reads it. A read from a library worker thread the victim started (no victim frame on that stack) is accepted and reported as `leak`;
- `gate.verify` skips only the check "nonce written via victim code"; every differential rule stays (hit on each fresh vulnerable copy, miss on the control, no violation, same flawed site as the reference exploit when it can be named).

**Reason.** Path traversal, cross-tenant reads and similar bugs return data to the caller; no victim code writes anything, so the nonce oracle cannot express them and the first design (the exploit writing the leaked data) was rejected by the "written outside victim code" rule. Approved by the user on 2026-10-25.

**What it does not cover.** A child process that reads the secret file is outside the Python guard (same known limit as in `docs`/README for nonce mode). The control run is the backstop: a script that gets the secret without the flaw gets it on the patched control too and is rejected (`test_child_process_reading_the_secret_is_caught_by_the_control`).

**Evidence** (`tests/test_leak_oracle.py`, `tests/test_aiohttp_case.py`): reference exploit VERIFIED; direct read = violation; `cat` child = rejected by the control; made-up value = miss; the secret is fresh per run and deleted; no marker = old behaviour (`test_nonce_mode_is_unchanged_without_the_marker`). The nonce-mode suites (`test_sandbox_gate.py`, `test_gate.py`, `test_blue_proof.py`) are unchanged and green.

**Red's contract.** `wreckless/agents/red.py` still describes only the nonce oracle (not changed: another agent owns it). For the leak case the instructions travel in the advisory text (`benchmarks/CVE-2024-23334/advisory.json`, which Red receives); a live Red run on this case has not been measured. Adding the leak contract to `CONTRACT` in red.py is the proper fix.

**Decided by:** the user, 2026-10-25.
