"""Exploit execution enclave: a userland guard rail (OpenShell when installed), not a sandbox.

Backends:
- ``userland-guard`` (default here): scrubbed env, rlimits, timeout, and a Python audit
  hook that blocks non-loopback sockets, writes outside the run directory, and (when
  asked) reads of the held-out benchmark files. It is a guard rail for Python payloads,
  not kernel isolation: ``os.system``/``subprocess`` children escape it (this host disallows unprivileged
  user namespaces, so bwrap/unshare are unavailable).
- ``openshell`` (preferred when the gateway is up): each item gets an OpenShell sandbox
  container (image ``wreckless-sandbox:py312``, see sandbox/Dockerfile) with kernel-enforced
  deny-all egress and a read-only root. The run directory is mirrored to /sandbox/w/<name>
  before every command; host paths in argv/env are rewritten to sandbox paths.

The guard also records oracle provenance: when the oracle file is opened for writing,
it captures the Python call stack and writes it to a provenance file whose path is
removed from the environment before the payload runs. The verify gate uses that to
reject "exploits" that simply write the nonce themselves.
"""
import json
import os
import resource
import secrets
import shutil
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
    _DENY = [os.path.realpath(d) for d in os.environ.get("WRECKLESS_DENY_READ", "").split(os.pathsep) if d]
    _ALLOW = {os.path.realpath(a) for a in os.environ.get("WRECKLESS_ALLOW_READ", "").split(os.pathsep) if a}
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
        if event == "open" and _DENY and not isinstance(args[0], int):
            p = os.path.realpath(os.fsdecode(args[0]))
            if p not in _ALLOW and any(p == d or p.startswith(d + os.sep) for d in _DENY):
                raise PermissionError(f"[enclave] read of held-out file blocked: {p}")
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
    returncode: int | None = None  # exploit process exit code (0 = it claims success)

    @property
    def verified(self) -> bool:
        return self.hit and self.via_victim is not None


class Enclave:
    """Run commands against a run directory, isolated by the best available backend.

    backend: "auto" (OpenShell if reachable, else userland guard), "openshell", "userland".
    Override with WRECKLESS_SANDBOX.
    """

    def __init__(self, root: Path, python: str, backend: str | None = None):
        self.root = root.resolve()
        self.python = python
        self.guard_dir = self.root / ".enclave"
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        (self.guard_dir / "sitecustomize.py").write_text(GUARD)
        (self.root / "tmp").mkdir(exist_ok=True)
        (self.root / "tmp" / ".keep").touch()  # empty dirs may not survive an upload
        want = backend or os.environ.get("WRECKLESS_SANDBOX", "auto")
        if want == "openshell" or (want == "auto" and openshell_available()):
            self.impl = _OpenShell(self.root)
        else:
            self.impl = _Userland(self.root, python)
        self.backend = self.impl.name

    def run(self, argv: list[str], env: dict | None = None, timeout: int = 120,
            cwd: Path | None = None) -> ExecResult:
        e = {
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "PYTHONPATH": str(self.guard_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "WRECKLESS_SANDBOX_ROOT": str(self.root),
            **(env or {}),
        }
        argv = [self.impl.python if a == self.python else a for a in argv]
        return self.impl.run(argv, e, timeout, cwd or self.root)

    def run_exploit(self, script: Path, victim: Path, extra_args: list[str] = (),
                    env: dict | None = None) -> OracleResult:
        """Run an exploit with a fresh oracle + nonce and report hit and provenance."""
        token = secrets.token_hex(6)
        if not script.resolve().is_relative_to(self.root):
            staged = self.guard_dir / "exploits" / f"{token}_{script.name}"
            staged.parent.mkdir(exist_ok=True)
            shutil.copy(script, staged)
            script = staged
        oracle = self.root / "tmp" / f"oracle_{token}"
        prov = self.root / ".enclave" / f"prov_{token}.json"
        nonce = secrets.token_hex(12)
        r = self.run([self.python, str(script), str(victim), *extra_args], env={
            "WRECKLESS_ORACLE": str(oracle), "WRECKLESS_NONCE": nonce,
            "WRECKLESS_PROVENANCE": str(prov), "WRECKLESS_VICTIM_ROOT": str(victim.resolve()),
            **(env or {})})
        # Read results in separate calls, after the payload exited, so its output can't forge them.
        hit = self.impl.read(oracle) == nonce
        raw = self.impl.read(prov)
        info = json.loads(raw) if raw else {}
        via = info.get("via_victim")
        return OracleResult(hit, self.impl.to_host(via) if via else None, r.output, r.backend,
                            info.get("frames", []), r.returncode)

    def close(self) -> None:
        self.impl.close()


class _Userland:
    name = "userland-guard"

    def __init__(self, root: Path, python: str):
        self.root, self.python = root, python

    def run(self, argv, env, timeout, cwd) -> ExecResult:
        env = {"PATH": "/usr/bin:/bin", **env}

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            os.setsid()

        try:
            p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                               timeout=timeout, preexec_fn=limits)
            return ExecResult(p.returncode, (p.stdout + p.stderr)[-6000:], self.name)
        except subprocess.TimeoutExpired as t:
            return ExecResult(124, f"TIMEOUT after {timeout}s\n{t.stdout or ''}", self.name)

    def read(self, path: Path) -> str | None:
        try:
            text = path.read_text()
        except FileNotFoundError:
            return None
        path.unlink()
        return text

    def to_host(self, path: str) -> str:
        return path

    def close(self) -> None:
        pass


SANDBOX_IMAGE = os.environ.get("WRECKLESS_SANDBOX_IMAGE", "wreckless-sandbox:py312")


def openshell_available() -> bool:
    if not shutil.which("openshell"):
        return False
    try:
        out = subprocess.run(["openshell", "status"], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return False
    return "Connected" in out


class _OpenShell:
    name = "openshell"
    python = "python3"

    def __init__(self, root: Path):
        import hashlib
        self.root = root
        self.remote = f"/sandbox/w/{root.name}"
        self.sandbox = "wl-" + hashlib.sha1(str(root).encode()).hexdigest()[:12]
        self.created = False

    def _cli(self, *args, timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(["openshell", "sandbox", *args], capture_output=True, text=True, timeout=timeout)

    def _ensure(self) -> None:
        if self.created:
            return
        if self._cli("get", self.sandbox, timeout=30).returncode != 0:
            r = self._cli("create", "--name", self.sandbox, "--from", SANDBOX_IMAGE, "--no-tty",
                          "--no-auto-providers", "--detach", "--label", "app=wreckless")
            if r.returncode != 0:
                raise RuntimeError(f"openshell create failed: {r.stderr or r.stdout}")
        self.created = True

    def _exec(self, cmd: list[str], timeout: int, env: dict | None = None, workdir: str | None = None):
        args = ["exec", "-n", self.sandbox, "--no-tty", "--timeout", str(timeout)]
        if workdir:
            args += ["--workdir", workdir]
        for k, v in (env or {}).items():
            args += ["--env", f"{k}={v}"]
        return self._cli(*args, "--", *cmd, timeout=timeout + 30)

    def _sync(self) -> None:
        self._exec(["rm", "-rf", self.remote], 30)
        r = self._cli("upload", "--no-git-ignore", self.sandbox, str(self.root), "/sandbox/w", timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"openshell upload failed: {r.stderr or r.stdout}")

    def _map(self, s: str) -> str:
        return s.replace(str(self.root), self.remote)

    def to_host(self, path: str) -> str:
        return path.replace(self.remote, str(self.root))

    def run(self, argv, env, timeout, cwd) -> ExecResult:
        self._ensure()
        self._sync()
        p = self._exec([self._map(a) for a in argv], timeout,
                       {k: self._map(v) for k, v in env.items()}, self._map(str(cwd)))
        return ExecResult(p.returncode, (p.stdout + p.stderr)[-6000:], self.name)

    def read(self, path: Path) -> str | None:
        p = self._exec(["cat", self._map(str(path))], 30)
        return p.stdout if p.returncode == 0 else None

    def close(self) -> None:
        if self.created:
            self._cli("delete", self.sandbox, timeout=60)
            self.created = False
