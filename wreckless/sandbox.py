"""Exploit execution enclave: a userland guard rail (OpenShell when installed), not a sandbox.

Backends:
- ``userland-guard`` (default here): scrubbed env, rlimits, timeout (whole process group
  killed), and a Python audit hook that blocks non-loopback sockets and DNS, writes outside
  <run>/tmp, frame/gc introspection and payload ctypes use, and (when asked) reads of the held-out
  benchmark files. It is a guard rail for Python payloads, not kernel isolation:
  ``os.system``/``subprocess`` children escape it (this host disallows unprivileged user
  namespaces, so bwrap/unshare are unavailable).
- ``openshell`` (preferred when the gateway is up): each item gets an OpenShell sandbox
  container (image ``wreckless-sandbox:py312``, see sandbox/Dockerfile) with kernel-enforced
  deny-all egress and a read-only root. The run directory is mirrored to /sandbox/w/<name>
  before every command; host paths in argv/env are rewritten to sandbox paths.

The guard also records oracle provenance: when the oracle file is opened for writing,
it walks the Python call stack and writes a keyed-blake2b-signed record (key delivered
over a pipe, path unrelated to the oracle's). Victim code only counts if every frame
between it and the write is stdlib/site-packages or code the victim compiled at runtime,
so a payload callback that victim code merely calls is not victim provenance. Any write
by the payload taints the oracle for the run, and any guard violation (reported on stderr
before the error is raised) rejects the run. The verify gate uses all of that to reject
"exploits" that write the nonce themselves.
"""
import ast
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

GUARD = textwrap.dedent('''
    def _install():
        # Everything lives in this closure: nothing is importable from `sitecustomize`, and
        # every callable the hook uses is bound here, so patching os/builtins later cannot
        # run payload code inside the hook. Only C functions and exact str/bytes are touched.
        import os, sys, posix, sysconfig, _thread, _socket
        from _stat import S_ISLNK, S_ISDIR
        from _blake2 import blake2b
        env = os.environ
        lstat, stat, readlink, getcwd = posix.lstat, posix.stat, posix.readlink, posix.getcwd
        p_open, p_read, p_write, p_close, p_exit, fstat = (posix.open, posix.read, posix.write,
                                                          posix.close, posix._exit, posix.fstat)
        compile_, getframe, ident, code_type = compile, sys._getframe, _thread.get_ident, type(_install.__code__)
        fsenc = sys.getfilesystemencoding()
        RD, WR = posix.O_RDONLY, posix.O_WRONLY | posix.O_RDWR | posix.O_CREAT | posix.O_APPEND | posix.O_TRUNC
        PERM, RTE = PermissionError, RuntimeError
        try:  # macOS has no /proc: a dir_fd's path comes from fcntl(F_GETPATH)
            from fcntl import fcntl as fcntl_, F_GETPATH
            GP_BUF = b"\\0" * 1024
        except ImportError:
            F_GETPATH = None

        def realpath(p):
            # non-strict realpath from C primitives (posixpath is patchable Python)
            if not p.startswith("/"):
                p = getcwd() + "/" + p
            todo, out, hops = p.split("/")[::-1], "", 0
            while todo:
                c = todo.pop()
                if c in ("", "."):
                    continue
                if c == "..":
                    out = out[:out.rfind("/")] if out else ""
                    continue
                cand = out + "/" + c
                try:
                    st = lstat(cand)
                except OSError:
                    out = cand
                    continue
                if S_ISLNK(st.st_mode) and hops < 40:
                    hops += 1
                    t = readlink(cand)
                    if t.startswith("/"):
                        out = ""
                    todo.extend(t.split("/")[::-1])
                else:
                    out = cand
            return out or "/"

        def isdir(p):
            try:
                return S_ISDIR(stat(p).st_mode)
            except OSError:
                return False

        def norm(s):
            # exact str copy: a str subclass could override __hash__/startswith/...
            return s if type(s) is str else str.__getitem__(s, slice(None))

        def sep(d):
            return d.rstrip("/") + "/"

        root = sep(realpath(norm(env["WRECKLESS_SANDBOX_ROOT"])))
        oracle = env.get("WRECKLESS_ORACLE")
        oracle = realpath(oracle) if oracle else None
        prov = env.pop("WRECKLESS_PROVENANCE", None)
        victim = env.pop("WRECKLESS_VICTIM_ROOT", None)
        victim = sep(realpath(victim)) if victim else None
        key = env.pop("WRECKLESS_PROV_KEY", "")
        kfd = env.pop("WRECKLESS_PROV_FD", None)
        if kfd:  # userland passes the key over a pipe so it is never in /proc/<pid>/environ
            key = p_read(int(kfd), 256).decode()
            p_close(int(kfd))
        deny = [sep(realpath(d)) for d in env.get("WRECKLESS_DENY_READ", "").split(os.pathsep) if d]
        allow = {realpath(a) for a in env.get("WRECKLESS_ALLOW_READ", "").split(os.pathsep) if a}
        writable = [sep(realpath(w)) for w in env.get("WRECKLESS_WRITABLE", root + "tmp").split(os.pathsep) if w]
        trusted = tuple(sep(realpath(v)) for k, v in sysconfig.get_paths().items()
                        if k in ("stdlib", "platstdlib", "purelib", "platlib"))
        try:
            st = fstat(2)
            err_id = (st.st_dev, st.st_ino)
        except OSError:
            err_id = None

        busy, genuine, dynamic, real = set(), {}, {}, {}
        state = {"via": None, "func": None, "tainted": False, "frames": []}
        path_types = []
        try:
            import pathlib
            for cls in (pathlib.PosixPath, pathlib.PurePosixPath):
                slot = pathlib.PurePath.__dict__["_str"]
                snap = [(c, n, c.__dict__.get(n)) for c in cls.__mro__ for n in ("__fspath__", "__str__")]
                path_types.append((cls, slot, snap))
        except (ImportError, KeyError):
            pass

        def as_path(a):
            # a str for the path the syscall used, or None if that can't be known without
            # running payload code (custom __fspath__ could answer differently the second time)
            t = type(a)
            if t is str:
                return a
            if t is bytes:
                return a.decode(fsenc, "surrogateescape")
            if issubclass(t, str):
                return str.__getitem__(a, slice(None))
            if issubclass(t, bytes):
                return bytes.__getitem__(a, slice(None)).decode(fsenc, "surrogateescape")
            for cls, slot, snap in path_types:
                if t is cls and all(c.__dict__.get(n) is v for c, n, v in snap):
                    try:
                        return norm(slot.__get__(a))
                    except AttributeError:
                        return None
            return None

        def inside(p, dirs):
            return any(p == d[:-1] or p.startswith(d) for d in dirs)

        def fd_path(fd):
            if F_GETPATH is None:
                return readlink("/proc/self/fd/%d" % fd)
            return fcntl_(fd, F_GETPATH, GP_BUF).split(b"\\0", 1)[0].decode(fsenc)

        def resolve(p, dir_fd=-1, follow=True):
            if not p.startswith("/") and dir_fd not in (None, -1):
                p = fd_path(dir_fd) + "/" + p
            if follow:
                return realpath(p)
            head, _, base = p.rstrip("/").rpartition("/")
            if base in ("", ".", ".."):
                return realpath(p)
            return realpath(head or ("/" if p.startswith("/") else ".")).rstrip("/") + "/" + base

        def violation(msg):
            # Report before raising: the host rejects any run with a guard violation, so a
            # payload that catches the error (and pokes at the traceback) gains nothing.
            line = ("[enclave-violation] " + msg + "\\n").encode("utf-8", "replace")
            try:
                st = fstat(2)
                if err_id is None or (st.st_dev, st.st_ino) != err_id:
                    raise OSError
                p_write(2, line)
            except OSError:
                p_exit(13)  # stderr was swapped out: can't report, so don't continue
            return PERM("[enclave] " + msg)

        def genuine_codes(fn):
            # every code object compiled from the victim file as it is on disk
            if fn not in genuine:
                found, todo = set(), []
                try:
                    fd, chunks = p_open(fn, RD), []
                    try:
                        while True:
                            b = p_read(fd, 1 << 20)
                            if not b:
                                break
                            chunks.append(b)
                    finally:
                        p_close(fd)
                    todo.append(compile_(b"".join(chunks), fn, "exec", dont_inherit=True))
                except (OSError, SyntaxError, ValueError):
                    pass
                while todo:
                    c = todo.pop()
                    found.add(c)
                    todo.extend(k for k in c.co_consts if type(k) is code_type)
                genuine[fn] = found
            return genuine[fn]

        def filereal(fn):
            if fn not in real:
                real[fn] = fn if fn.startswith("<") else realpath(fn)
            return real[fn]

        def caller():
            # the frame that triggered the event (check <- hook <- caller); none at top level
            try:
                return getframe(3)
            except ValueError:
                return None

        def victim_context(f):
            # Walk outward from f. Victim code counts only if every frame before it is stdlib/
            # site-packages or code the victim itself compiled at runtime (eval/exec): a payload
            # callback (__str__, __eq__, ...) invoked by victim code does not qualify.
            frames = []
            while f is not None:
                code = f.f_code
                fn = filereal(norm(code.co_filename))
                frames.append(fn)
                if victim and fn.startswith(victim) and code in genuine_codes(fn):
                    return fn, norm(code.co_qualname), frames
                if dynamic.get(id(code)) is code or fn.startswith("<frozen ") or fn.startswith(trusted):
                    f = f.f_back
                    continue
                return None, None, frames
            return None, None, frames

        def ctypes_ok(f):
            # ctypes is fine while a module is being imported (numpy loads it) or when victim
            # code uses it; the payload's own code (directly or through a library) may not
            while f is not None:
                code = f.f_code
                fn = filereal(norm(code.co_filename))
                if fn.startswith("<frozen importlib"):
                    return True
                if dynamic.get(id(code)) is code or (victim and fn.startswith(victim) and code in genuine_codes(fn)):
                    return True
                if not (fn.startswith("<frozen ") or fn.startswith(trusted)):
                    return False
                f = f.f_back
            return False

        def record():
            if not (prov and key):
                return
            via, func = (None, None) if state["tainted"] else (state["via"], state["func"])
            data = repr((via, func, state["frames"][:30])).encode()
            blob = blake2b(data, key=key.encode()).hexdigest().encode() + b"\\n" + data
            fd = p_open(prov, posix.O_WRONLY | posix.O_CREAT | posix.O_TRUNC, 0o600)
            try:
                p_write(fd, blob)
            finally:
                p_close(fd)

        def touch_oracle(f):
            via, func, frames = victim_context(f)
            if via is None:
                state["tainted"] = True  # sticky: once the payload touched it, no victim write counts
            elif state["via"] is None:
                state["via"], state["func"] = via, func
            state["frames"] = frames
            record()

        def taint():
            state["tainted"] = True
            record()

        def check_write(p, what):
            if victim and inside(p, [victim]):
                raise violation("victim source is read-only: " + p)
            if not (p == "/dev/null" or inside(p, writable)):
                raise violation(what + " outside sandbox blocked: " + p)

        # event -> ((arg index, follow symlinks), ...), dir_fd arg index or None
        MUTATE = {"os.rename": (((0, False), (1, False)), 2), "os.remove": (((0, False),), 1),
                  "os.rmdir": (((0, False),), 1), "os.mkdir": (((0, False),), 2),
                  "os.chmod": (((0, True),), 2), "os.chown": (((0, True),), 3),
                  "os.utime": (((0, True),), 3), "os.truncate": (((0, True),), None),
                  "os.link": (((0, True), (1, False)), 2), "os.symlink": (((1, False),), 2),
                  "os.setxattr": (((0, True),), None), "os.removexattr": (((0, True),), None)}
        INTROSPECT = {"gc.get_objects", "gc.get_referrers", "gc.get_referents", "sys.settrace",
                      "sys.setprofile", "sys._current_frames", "sys._current_exceptions",
                      "sys.monitoring.register_callback"}
        NET = {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"}
        LOOPBACK = ("127.0.0.1", "::1", "localhost")
        inet_pton, families = _socket.inet_pton, (_socket.AF_INET, _socket.AF_INET6)

        def is_ip(h):
            for fam in families:
                try:
                    inet_pton(fam, h)
                    return True
                except OSError:
                    pass
            return False

        def check(event, args):
            if event == "open":
                a, mode, flags = args
                if type(a) is int:
                    return
                p = as_path(a)
                writing = bool(flags & WR)
                if p is None:
                    if writing or deny:
                        raise violation("open of an opaque path object blocked")
                    return
                if writing:
                    if not p.startswith("/") and ".." in p.split("/"):
                        raise violation("relative '..' write blocked: " + p)  # dir_fd isn't audited
                    rp = realpath(p)
                    check_write(rp, "write")
                    if oracle and rp == oracle:
                        touch_oracle(caller())
                    return
                if deny or "proc" in p or mode is None:
                    rp = realpath(p)
                    if deny and rp not in allow and inside(rp, deny):
                        raise violation("read of held-out file blocked: " + rp)
                    if rp.startswith("/proc/") and rp.rsplit("/", 1)[-1] in ("environ", "mem"):
                        raise violation("read of process memory/environment blocked: " + rp)
                    if mode is None and isdir(rp) and not inside(rp, writable):
                        raise violation("directory fd outside sandbox blocked: " + rp)
            elif event in MUTATE:
                spec, fdi = MUTATE[event]
                dir_fd = args[fdi] if fdi is not None and fdi < len(args) else -1
                for i, follow in spec:
                    a = args[i] if i < len(args) else None
                    if type(a) is int or a is None:
                        continue
                    p = as_path(a)
                    if p is None:
                        raise violation(event + " on an opaque path object blocked")
                    rp = resolve(p, dir_fd, follow)
                    if oracle and rp == oracle:
                        taint()
                    check_write(rp, event)
                if event == "os.symlink":  # link targets stay inside the writable area
                    t = as_path(args[0])
                    if t is None or not t.startswith("/") or not inside(realpath(t), writable):
                        raise violation("symlink target must be an absolute sandbox path")
            elif event == "exec":
                c = args[0]
                if type(c) is code_type:
                    fn = norm(c.co_filename)
                    # runtime-compiled source only: a module file the payload planted on sys.path
                    # and got the victim to import is still payload code
                    if fn.startswith("<") or _missing(fn):
                        if victim_context(caller())[0]:  # (via, func, frames)
                            todo = [c]
                            while todo:
                                k = todo.pop()
                                dynamic[id(k)] = k
                                todo.extend(x for x in k.co_consts if type(x) is code_type)
            elif event in NET:
                addr = args[1]
                host = addr[0] if type(addr) is tuple and addr and type(addr[0]) is str else None
                if host not in LOOPBACK:
                    raise violation("egress blocked: %s %r" % (event, addr if type(addr) in (tuple, str, bytes) else "?"))
            elif event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
                           "socket.gethostbyaddr"):
                # IP literals resolve locally; connect() still checks where they go
                if not (type(args[0]) is str and (args[0] in LOOPBACK or is_ip(args[0]))):
                    raise violation("DNS lookup blocked: %r" % (args[0] if type(args[0]) in (str, bytes) else "?"))
            elif event.startswith("ctypes."):
                if not ctypes_ok(caller()):
                    raise violation("ctypes blocked: " + event)
            elif event in INTROSPECT:
                raise violation("introspection blocked: " + event)
            elif event == "sys.addaudithook":
                raise RTE("[enclave] adding audit hooks is blocked")

        def _missing(fn):
            try:
                stat(fn)
                return False
            except OSError:
                return True

        def hook(event, args):
            me = ident()
            if me in busy:
                return
            busy.add(me)
            try:
                check(event, args)
            except (PERM, RTE):
                raise
            except BaseException:
                raise violation("guard error on " + event)
            finally:
                busy.discard(me)

        sys.addaudithook(hook)

    _install()
    del _install
''')


VIOLATION = "[enclave-violation]"


@dataclass
class ExecResult:
    returncode: int
    output: str
    backend: str
    violation: bool = False  # the guard blocked something (reported on stderr before raising)


@dataclass
class OracleResult:
    hit: bool               # nonce landed in the oracle file
    via_victim: str | None  # victim source file on the stack when it was written
    output: str
    backend: str
    frames: list = field(default_factory=list)
    returncode: int | None = None  # exploit process exit code (0 = it claims success)
    violation: bool = False        # the payload tripped the guard at least once
    via_func: str | None = None    # innermost genuine victim function when the oracle was written

    @property
    def verified(self) -> bool:
        return self.hit and self.via_victim is not None and not self.violation


def _verify_record(raw: str | None, key: str) -> dict:
    """Provenance written by the guard: '<keyed blake2b>\\n<repr((via, func, frames))>'."""
    if not raw or "\n" not in raw:
        return {}
    mac, data = raw.split("\n", 1)
    want = hashlib.blake2b(data.encode(), key=key.encode()).hexdigest()
    if not hmac.compare_digest(mac, want):
        return {}
    try:
        via, func, frames = ast.literal_eval(data)
    except (ValueError, SyntaxError, TypeError):
        return {}
    if not all(v is None or isinstance(v, str) for v in (via, func)) or not isinstance(frames, list):
        return {}
    return {"via_victim": via, "via_func": func, "frames": [str(f) for f in frames]}


class Enclave:
    """Run commands against a run directory, isolated by the best available backend.

    backend: "auto" (OpenShell if reachable, else userland guard), "openshell", "userland".
    Override with WRECKLESS_SANDBOX.
    """

    def __init__(self, root: Path, python: str, backend: str | None = None, image: str | None = None):
        self.root = root.resolve()
        self.python = python
        self.guard_dir = self.root / ".enclave"
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        self._write_guard()
        (self.root / "tmp").mkdir(exist_ok=True)
        (self.root / "tmp" / ".keep").touch()  # empty dirs may not survive an upload
        self.impl = (_OpenShell(self.root, image or SANDBOX_IMAGE) if select_backend(backend) == "openshell"
                     else _Userland(self.root, python))
        self.backend = self.impl.name

    def _write_guard(self) -> None:
        # rewritten before every run: never trust a copy a previous payload could have touched
        (self.guard_dir / "sitecustomize.py").write_text(GUARD)

    def run(self, argv: list[str], env: dict | None = None, timeout: int = 120,
            cwd: Path | None = None, secret: str | None = None) -> ExecResult:
        """Payload writes are confined to <root>/tmp (override with WRECKLESS_WRITABLE)."""
        self._write_guard()
        e = {
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "PYTHONPATH": str(self.guard_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "WRECKLESS_SANDBOX_ROOT": str(self.root),
            "WRECKLESS_WRITABLE": str(self.root / "tmp"),
            **(env or {}),
        }
        argv = [self.impl.python if a == self.python else a for a in argv]
        return self.impl.run(argv, e, timeout, (cwd or self.root).resolve(), secret)

    def run_exploit(self, script: Path, victim: Path, extra_args: list[str] = (),
                    env: dict | None = None) -> OracleResult:
        """Run an exploit with a fresh oracle + nonce and report hit and provenance."""
        script, victim = Path(script).resolve(), Path(victim).resolve()
        token = secrets.token_hex(6)
        if not script.is_relative_to(self.root):
            staged = self.guard_dir / "exploits" / f"{token}_{script.name}"
            staged.parent.mkdir(exist_ok=True)
            shutil.copy(script, staged)
            script = staged
        oracle = self.root / "tmp" / f"oracle_{token}"
        # unrelated token: the provenance path must not be derivable from the oracle's
        prov = self.guard_dir / f"prov_{secrets.token_hex(12)}.json"
        nonce, key = secrets.token_hex(12), secrets.token_hex(16)
        r = self.run([self.python, str(script), str(victim), *extra_args], env={
            "WRECKLESS_ORACLE": str(oracle), "WRECKLESS_NONCE": nonce,
            "WRECKLESS_PROVENANCE": str(prov), "WRECKLESS_VICTIM_ROOT": str(victim),
            **(env or {})}, secret=key)
        # Read results in separate calls, after the payload exited, so its output can't forge them.
        hit = self.impl.read(oracle) == nonce
        info = _verify_record(self.impl.read(prov), key)
        via = info.get("via_victim")
        return OracleResult(hit, self.impl.to_host(via) if via else None, r.output, r.backend,
                            info.get("frames", []), r.returncode, r.violation, info.get("via_func"))

    def close(self) -> None:
        self.impl.close()


def _tail(out: str) -> tuple[str, bool]:
    # violations are judged on the full output: a payload can't scroll them out of the tail
    return out[-6000:], VIOLATION in out


class _Userland:
    name = "userland-guard"

    def __init__(self, root: Path, python: str):
        self.root, self.python = root, python

    def run(self, argv, env, timeout, cwd, secret=None) -> ExecResult:
        env = {"PATH": "/usr/bin:/bin", **env}
        limits = [f"--cpu={timeout}", f"--fsize={64 << 20}"]
        # prlimit instead of preexec_fn: preexec_fn is unsafe in the multithreaded daemon
        argv = ["prlimit", *limits, "--", *argv] if shutil.which("prlimit") else argv
        fds = ()
        if secret:  # the guard reads its key from a pipe, so it never sits in /proc/<pid>/environ
            rfd, wfd = os.pipe()
            os.write(wfd, secret.encode())
            os.close(wfd)
            env["WRECKLESS_PROV_FD"], fds = str(rfd), (rfd,)
        try:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True, pass_fds=fds)
        finally:
            for fd in fds:
                os.close(fd)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _killpg(p.pid)  # the whole session: grandchildren too
            out, err = p.communicate()
            tail, bad = _tail(out + err)
            return ExecResult(124, f"TIMEOUT after {timeout}s\n{tail}", self.name, bad)
        _killpg(p.pid)  # reap anything the payload left running in its session
        tail, bad = _tail(out + err)
        return ExecResult(p.returncode, tail, self.name, bad)

    def read(self, path: Path) -> str | None:
        # O_NOFOLLOW + regular-file check: a payload-planted symlink or FIFO can't redirect or hang it
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "r", errors="replace", closefd=False) as fh:
                text = fh.read(1 << 20)
        finally:
            os.close(fd)
        path.unlink(missing_ok=True)
        return text

    def to_host(self, path: str) -> str:
        return path

    def close(self) -> None:
        pass


def _killpg(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


SANDBOX_IMAGE = os.environ.get("WRECKLESS_SANDBOX_IMAGE", "wreckless-sandbox:py312")
SANDBOX_POLICY = Path(__file__).resolve().parent.parent / "sandbox" / "policy.yaml"


def select_backend(backend: str | None = None) -> str:
    """The backend Enclave will use: explicit arg, else WRECKLESS_SANDBOX, else auto-detect."""
    want = backend or os.environ.get("WRECKLESS_SANDBOX", "auto")
    return "openshell" if want == "openshell" or (want == "auto" and openshell_available()) else "userland"


def openshell_available() -> bool:
    if not shutil.which("openshell"):
        return False
    try:
        out = subprocess.run(["openshell", "status"], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return False
    return "Connected" in out


OWNER_LABEL = "wreckless-owner"


def _owner(pid: int | None = None) -> str | None:
    """<pid>-<start time>: a recycled pid doesn't pass for the process that made the sandbox."""
    pid = pid or os.getpid()
    try:
        return f"{pid}-{Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]}"
    except (OSError, IndexError):
        return None


def _owner_alive(owner: str | None) -> bool:
    pid = (owner or "").split("-", 1)[0]
    return pid.isdigit() and _owner(int(pid)) == owner


def _labels(get_json: str) -> dict:
    try:
        return json.loads(get_json).get("labels") or {}
    except (ValueError, AttributeError):
        return {}


def prune_orphan_sandboxes() -> int:
    """Delete WreckLess sandboxes whose owner process is gone. close() runs in a finally, so a
    SIGKILLed run (or one whose gateway call timed out) leaves its sandbox behind for good."""
    if not openshell_available():
        return 0
    try:
        out = subprocess.run(["openshell", "sandbox", "list", "--selector", "app=wreckless",
                              "--page-size", "10000", "-o", "json"],
                             capture_output=True, text=True, timeout=60).stdout
        boxes = json.loads(out).get("sandboxes") or []
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return 0
    dead = [b["name"] for b in boxes if not _owner_alive((b.get("labels") or {}).get(OWNER_LABEL))]

    def delete(name: str) -> None:
        try:
            subprocess.run(["openshell", "sandbox", "delete", name], capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            pass

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(16) as ex:  # ~12 s each (docker's graceful stop)
        list(ex.map(delete, dead))
    return len(dead)


class _OpenShell:
    name = "openshell"
    python = "python3"

    def __init__(self, root: Path, image: str = SANDBOX_IMAGE):
        import hashlib
        self.root, self.image = root, image
        self.remote = f"/sandbox/w/{root.name}"
        self.sandbox = "wl-" + hashlib.sha1(str(root).encode()).hexdigest()[:12]
        self.created = False

    def _cli(self, *args, timeout: int = 300) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(["openshell", "sandbox", *args], capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired as t:
            return subprocess.CompletedProcess(t.cmd, 124, t.stdout or "", f"TIMEOUT after {timeout}s")

    def _ensure(self) -> None:
        if self.created:
            return
        g = self._cli("get", self.sandbox, "-o", "json", timeout=30)
        if g.returncode == 0 and not _owner_alive(_labels(g.stdout).get(OWNER_LABEL)):
            self._cli("delete", self.sandbox, timeout=120)  # left by a killed run: never inherit its state
            g = self._cli("get", self.sandbox, timeout=30)
        if g.returncode != 0:
            r = self._cli("create", "--name", self.sandbox, "--from", self.image, "--no-tty", "--policy", str(SANDBOX_POLICY),
                          "--no-auto-providers", "--detach", "--label", "app=wreckless",
                          "--label", f"{OWNER_LABEL}={_owner()}")
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

    def run(self, argv, env, timeout, cwd, secret=None) -> ExecResult:
        self._ensure()
        self._sync()
        env = {k: self._map(v) for k, v in env.items()}
        if secret:  # no fd passing through the CLI; the guard pops it from its env at startup
            env["WRECKLESS_PROV_KEY"] = secret
        p = self._exec([self._map(a) for a in argv], timeout, env, self._map(str(cwd)))
        tail, bad = _tail((p.stdout or "") + (p.stderr or ""))
        return ExecResult(p.returncode, tail, self.name, bad)

    def read(self, path: Path) -> str | None:
        p = self._exec(["cat", self._map(str(path))], 30)
        return p.stdout if p.returncode == 0 else None

    def close(self) -> None:
        if self.created:
            self._cli("delete", self.sandbox, timeout=60)
            self.created = False
