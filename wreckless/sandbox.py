"""Exploit execution enclave.

Backends:
- ``userland-guard`` (default here): scrubbed env, rlimits, timeout, and a Python audit
  hook that blocks non-loopback sockets and writes outside the run directory. It is a
  guard rail for Python payloads, not kernel isolation (this host disallows unprivileged
  user namespaces, so bwrap/unshare are unavailable).
- ``openshell``: TODO once the gateway is installed (see wreckless-gb10-plan.md).

The guard also records oracle provenance: when the oracle file is opened for writing,
it captures the Python call stack and writes it to a provenance file whose path is
removed from the environment before the payload runs. The verify gate uses that to
reject "exploits" that simply write the nonce themselves.
"""
import json
import os
import resource
import secrets
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

GUARD = textwrap.dedent('''
    import os, sys, json
    _ROOT = os.environ["WRECKLESS_SANDBOX_ROOT"]
    _ORACLE = os.environ.get("WRECKLESS_ORACLE")
    _PROV = os.environ.pop("WRECKLESS_PROVENANCE", None)
    _VICTIM = os.environ.pop("WRECKLESS_VICTIM_ROOT", None)
    _WRITE = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    _busy = []

    _VSEP = _VICTIM.rstrip(os.sep) + os.sep if _VICTIM else None
    _genuine = {}

    def _in_victim(path):
        return bool(_VSEP) and os.path.realpath(path).startswith(_VSEP)

    def _genuine_codes(filename):
        """Every code object compiled from the victim file as it is on disk."""
        if filename not in _genuine:
            found, todo = set(), []
            try:
                with open(filename, "rb") as fh:
                    todo.append(compile(fh.read(), filename, "exec", dont_inherit=True))
            except (OSError, SyntaxError, ValueError):
                pass
            while todo:
                c = todo.pop()
                found.add(c)
                todo.extend(k for k in c.co_consts if isinstance(k, type(c)))
            _genuine[filename] = found
        return _genuine[filename]

    def _provenance():
        # A frame only counts as victim code if its code object equals one compiled from
        # the victim's source on disk; co_filename alone is forgeable via compile().
        frames, via, f = [], None, sys._getframe(2)
        _busy.append(1)
        try:
            while f is not None:
                fn = f.f_code.co_filename
                frames.append(fn)
                if via is None and _in_victim(fn) and f.f_code in _genuine_codes(fn):
                    via = fn
                f = f.f_back
            with open(_PROV, "w") as fh:
                json.dump({"via_victim": via, "frames": frames[:30]}, fh)
        finally:
            _busy.pop()

    _MUTATE = {"os.rename": (0, 1), "os.replace": (0, 1), "os.remove": (0,), "os.rmdir": (0,),
               "os.chmod": (0,), "os.truncate": (0,), "os.link": (0, 1), "os.symlink": (1,),
               "shutil.rmtree": (0,), "shutil.move": (0, 1), "shutil.copyfile": (1,)}

    def _hook(event, args):
        if _busy:
            return
        if event == "open" and args[2] and (args[2] & _WRITE) and not isinstance(args[0], int):
            p = os.path.realpath(os.fsdecode(args[0]))
            if not (p.startswith(_ROOT) or p == "/dev/null"):
                raise PermissionError(f"[enclave] write outside sandbox blocked: {p}")
            if _in_victim(p):
                raise PermissionError(f"[enclave] victim source is read-only: {p}")
            if _ORACLE and _PROV and p == os.path.realpath(_ORACLE):
                _provenance()
        elif event in _MUTATE:
            for i in _MUTATE[event]:
                a = args[i] if i < len(args) else None
                if isinstance(a, (str, bytes, os.PathLike)) and _in_victim(os.fsdecode(a)):
                    raise PermissionError(f"[enclave] victim source is read-only: {os.fsdecode(a)}")
        elif event == "socket.connect":
            addr = args[1]
            if isinstance(addr, tuple) and addr[0] not in ("127.0.0.1", "::1", "localhost"):
                raise PermissionError(f"[enclave] egress blocked: {addr}")
    sys.addaudithook(_hook)
''')


@dataclass
class ExecResult:
    returncode: int
    output: str
    backend: str


@dataclass
class OracleResult:
    hit: bool               # nonce landed in the oracle file
    via_victim: str | None  # victim source file on the stack when it was written
    output: str
    backend: str
    frames: list = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.hit and self.via_victim is not None


class Enclave:
    def __init__(self, root: Path, python: str):
        self.root = root.resolve()
        self.python = python
        self.guard_dir = self.root / ".enclave"
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        (self.guard_dir / "sitecustomize.py").write_text(GUARD)
        (self.root / "tmp").mkdir(exist_ok=True)
        self.backend = "userland-guard"

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

    def run_exploit(self, script: Path, victim: Path, extra_args: list[str] = (),
                    env: dict | None = None) -> OracleResult:
        """Run an exploit with a fresh oracle + nonce and report hit and provenance."""
        token = secrets.token_hex(6)
        oracle = self.root / "tmp" / f"oracle_{token}"
        prov = self.root / ".enclave" / f"prov_{token}.json"
        nonce = secrets.token_hex(12)
        r = self.run([self.python, str(script), str(victim), *extra_args], env={
            "WRECKLESS_ORACLE": str(oracle), "WRECKLESS_NONCE": nonce,
            "WRECKLESS_PROVENANCE": str(prov), "WRECKLESS_VICTIM_ROOT": str(victim.resolve()),
            **(env or {})})
        hit = oracle.exists() and oracle.read_text() == nonce
        info = json.loads(prov.read_text()) if prov.exists() else {}
        for f in (oracle, prov):
            f.unlink(missing_ok=True)
        return OracleResult(hit, info.get("via_victim"), r.output, r.backend, info.get("frames", []))

