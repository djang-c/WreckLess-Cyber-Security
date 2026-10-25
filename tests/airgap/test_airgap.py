"""Container test for scripts/airgap_lockdown.sh (never touches the host firewall).

Runs the scenario in tests/airgap/run_in_container.sh inside a --cap-add NET_ADMIN
Docker container. Skipped (not failed) when Docker is unavailable, or when
WRECKLESS_SKIP_AIRGAP=1. Needs internet access from the container.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

RUN_SH = Path(__file__).with_name("run_in_container.sh")
CHECKS = [
    "a_openai_blocked_v4",
    "a_openai_blocked_v6",  # SKIP verdict allowed when the container has no IPv6
    "a_v6_rules_present",
    "b_localhost_8000",
    "c_slack",
    "d_idempotent",
    "e_off_restores",
    "f_verify_exit0",
    "f_verify_root_counter",
    "f_verify_foreign_reject_fails",
    "f_verify_fails_when_off",
    "g_dryrun_nonroot",
    "h_airtight",
]


def _docker() -> str | None:
    return shutil.which("docker") or (
        "/usr/local/bin/docker" if os.path.exists("/usr/local/bin/docker") else None
    )


def _skip_reason() -> str | None:
    if os.environ.get("WRECKLESS_SKIP_AIRGAP") == "1":
        return "WRECKLESS_SKIP_AIRGAP=1"
    docker = _docker()
    if docker is None:
        return "docker CLI not found; airgap container test skipped"
    try:
        probe = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker info failed: {exc}"
    if probe.returncode != 0:
        tail = (probe.stderr.strip().splitlines() or ["?"])[-1]
        return f"docker daemon unavailable (docker info failed): {tail}"
    return None


@pytest.fixture(scope="module")
def results() -> dict[str, tuple[str, str]]:
    why = _skip_reason()
    if why is not None:
        pytest.skip(why)
    env = {**os.environ, "DOCKER": _docker() or "docker"}
    proc = subprocess.run(
        ["bash", str(RUN_SH)], capture_output=True, text=True, timeout=900, env=env
    )
    print(proc.stdout)
    print(proc.stderr)
    out: dict[str, tuple[str, str]] = {}
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT "):
            _, name, verdict, *rest = line.split(" ", 3)
            out[name] = (verdict, rest[0] if rest else "")
    assert out, f"no RESULT lines; rc={proc.returncode}\n{proc.stderr}"
    assert "baseline" not in out, f"baseline invalid: {out['baseline']}"
    return out


@pytest.mark.parametrize("check", CHECKS)
def test_airgap_check(results: dict[str, tuple[str, str]], check: str) -> None:
    verdict, detail = results.get(check, ("MISSING", ""))
    if verdict == "SKIP":
        pytest.skip(f"{check}: {detail}")
    assert verdict == "PASS", f"{check}: {verdict} {detail}"
