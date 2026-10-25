"""scripts/install_services.sh: the generated systemd units (dry run; changes nothing)."""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "install_services.sh"


def dry(*args):
    p = subprocess.run(["bash", str(SCRIPT), "--dry-run", *args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


def test_default_install_has_no_airgap_and_never_runs_daemon_as_root():
    out = dry()
    assert "wreckless-models.service" in out and "wreckless-daemon.service" in out
    assert "wreckless-airgap.service" not in out          # opt-in: it blocks Claude Code on the box
    daemon = out.split("── wreckless-daemon.service ──")[1]
    assert "User=root" not in daemon and "Restart=always" in daemon
    assert "daemon --porter" in daemon and "--slack-listener" not in daemon and ". ./.env" in daemon
    slack = out.split("── wreckless-slack.service ──")[1].split("──")[0]
    assert "python -m wreckless.slack_socket" in slack       # the Slack side runs as its own process
    assert "xoxb-" not in out and "xapp-" not in out      # tokens stay in .env, never in a unit


def test_with_airgap_orders_daemon_after_airgap():
    out = dry("--with-airgap")
    daemon = out.split("── wreckless-daemon.service ──")[1].split("──")[0]
    assert "After=wreckless-models.service network-online.target wreckless-airgap.service" in daemon
    air = out.split("── wreckless-airgap.service ──")[1]
    assert "airgap_lockdown.sh on" in air and "airgap_lockdown.sh off" in air and "Restart=on-failure" in air


def test_every_sudo_step_is_printed():
    out = dry()
    assert "+ sudo systemctl enable --now wreckless-daemon.service" in out


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="systemd-analyze only on Linux")
def test_units_pass_systemd_analyze(tmp_path):
    out = dry("--with-airgap")
    for name in ("wreckless-models", "wreckless-daemon", "wreckless-slack", "wreckless-airgap"):
        unit = out.split(f"── {name}.service ──")[1].split("\n── ")[0].split("\nNOTE:")[0].split("\n+ ")[0]
        f = tmp_path / f"{name}.service"
        f.write_text(unit.strip() + "\n")
        p = subprocess.run(["systemd-analyze", "verify", str(f)], capture_output=True, text=True)
        assert "Unknown" not in p.stderr and "Invalid" not in p.stderr, p.stderr
