"""Exploit execution enclave.

Uses OpenShell when its CLI is installed. Otherwise falls back to a userland
enclave: scrubbed env, rlimits, timeout, and a Python audit hook that blocks
non-loopback sockets and writes outside the run directory. The fallback is a
guard rail for Python payloads, not kernel isolation (this host disallows
unprivileged user namespaces, so bwrap/unshare are unavailable).
"""
import os
import resource
import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

GUARD = textwrap.dedent('''
    import os, sys, socket
    _ROOT = os.environ["WRECKLESS_SANDBOX_ROOT"]
    _WRITE = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    def _hook(event, args):
        if event == "open" and args[2] and (args[2] & _WRITE):
            p = os.path.realpath(os.fsdecode(args[0])) if not isinstance(args[0], int) else ""
            if p and not (p.startswith(_ROOT) or p == "/dev/null"):
                raise PermissionError(f"[enclave] write outside sandbox blocked: {p}")
        elif event == "socket.connect":
            addr = args[1]
            host = addr[0] if isinstance(addr, tuple) else str(addr)
            if isinstance(addr, tuple) and host not in ("127.0.0.1", "::1", "localhost"):
                raise PermissionError(f"[enclave] egress blocked: {addr}")
    sys.addaudithook(_hook)
''')


@dataclass
class ExecResult:
    returncode: int
    output: str
    backend: str


class Enclave:
    def __init__(self, root: Path, python: str):
        self.root = root.resolve()
        self.python = python
        self.guard_dir = self.root / ".enclave"
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        (self.guard_dir / "sitecustomize.py").write_text(GUARD)
        (self.root / "tmp").mkdir(exist_ok=True)
        self.backend = "openshell" if shutil.which("openshell") else "userland-guard"

    def run(self, argv: list[str], env: dict | None = None, timeout: int = 120,
            cwd: Path | None = None) -> ExecResult:
        e = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "PYTHONPATH": str(self.guard_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "WRECKLESS_SANDBOX_ROOT": str(self.root),
            **(env or {}),
        }
        if self.backend == "openshell":
            # TODO: confirm OpenShell CLI flags once installed; policy from Blue lives in runs/<id>/
            argv = ["openshell", "run", "--policy", str(self.root / "openshell_policy.yaml"), "--", *argv]

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            os.setsid()

        try:
            p = subprocess.run(argv, cwd=cwd or self.root, env=e, capture_output=True, text=True,
                               timeout=timeout, preexec_fn=limits)
            return ExecResult(p.returncode, (p.stdout + p.stderr)[-6000:], self.backend)
        except subprocess.TimeoutExpired as t:
            return ExecResult(124, f"TIMEOUT after {timeout}s\n{t.stdout or ''}", self.backend)
