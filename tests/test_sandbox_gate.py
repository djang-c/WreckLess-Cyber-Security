"""Regression: guard and provenance bypasses found in review, each one a payload that used to
get VERIFIED or write outside the sandbox. All run on the userland guard (the weaker backend)."""
import os
import subprocess
import sys
import textwrap
import time

import pytest

from wreckless import gate
from wreckless.gitops import git, init_victim, worktree
from wreckless.sandbox import Enclave, _verify_record

VICTIM = {
    "vpkg/__init__.py": (
        "def describe(x):\n    return str(x)\n\n"           # benign: formats attacker input
        "def calc(expr):\n    return eval(expr)\n"),           # the real bug: eval injection
}


@pytest.fixture
def box(tmp_path):
    victim = tmp_path / "victim"
    for rel, src in VICTIM.items():
        (victim / rel).parent.mkdir(parents=True, exist_ok=True)
        (victim / rel).write_text(src)
    enclave = Enclave(tmp_path, sys.executable, backend="userland")
    yield tmp_path, victim, enclave
    enclave.close()


def exploit(root, body):
    script = root / "x.py"
    script.write_text("import os, sys\nsys.path.insert(0, sys.argv[1])\nimport vpkg\n"
                      "ORACLE, NONCE = os.environ['WRECKLESS_ORACLE'], os.environ['WRECKLESS_NONCE']\n"
                      + textwrap.dedent(body))
    return script


def verdict(box_, body):
    root, victim, enclave = box_
    return gate.verify(exploit(root, body), victim, enclave, runs=1)


def test_real_eval_injection_still_verifies(box):
    v = verdict(box, "vpkg.calc(f\"__import__('pathlib').Path({ORACLE!r}).write_text({NONCE!r})\")\n")
    assert v.passed and v.result.via_func == "calc", v.result.output   # no reference exploit: REACHABLE


def test_payload_callback_called_by_victim_is_not_victim_provenance(box):
    v = verdict(box, """
        class E:
            def __str__(self):
                open(ORACLE, 'w').write(NONCE)
                return ''
        vpkg.describe(E())
    """)
    assert v.result.hit and not v.verified


def test_callback_compiled_with_exec_is_not_victim_provenance(box):
    v = verdict(box, """
        ns = {'ORACLE': ORACLE, 'NONCE': NONCE}
        exec("class E:\\n def __str__(s):\\n  open(ORACLE,'w').write(NONCE); return ''", ns)
        vpkg.describe(ns['E']())
    """)
    assert v.result.hit and not v.verified


def test_planted_module_imported_by_victim_is_not_victim_code(box):
    v = verdict(box, """
        d = os.path.join(os.environ['TMPDIR'], 'planted')
        os.makedirs(d, exist_ok=True)   # the gate runs it on several copies
        open(os.path.join(d, 'evil.py'), 'w').write(
            f"open({ORACLE!r},'w').write({NONCE!r})\\n")
        sys.path.insert(0, d)
        vpkg.calc("__import__('evil')")
    """)
    assert v.result.hit and not v.verified


def test_guard_state_is_not_importable(box):
    root, victim, enclave = box
    r = enclave.run([sys.executable, "-c",
                     "import sitecustomize as s; print(sorted(k for k in vars(s) if not k.startswith('__')))"])
    assert r.returncode == 0 and r.output.strip() == "[]", r.output


def test_exploit_cannot_forge_provenance_file(box):
    v = verdict(box, """
        open(ORACLE, 'w').write(NONCE)
        enc = os.path.join(os.path.dirname(os.path.dirname(ORACLE)), '.enclave')
        for name in os.listdir(enc):
            try:
                open(os.path.join(enc, name), 'w').write('x' * 64 + '\\n("/v/vpkg/__init__.py", [])')
            except PermissionError:
                pass
    """)
    assert not v.verified


def test_unsigned_provenance_record_is_ignored():
    assert _verify_record('0' * 128 + '\n("/v/vpkg/__init__.py", "f", [])', "k" * 32) == {}


def test_payload_write_before_victim_write_taints_the_oracle(box):
    v = verdict(box, """
        open(ORACLE, 'w').write(NONCE)
        vpkg.calc(f"open({ORACLE!r}, 'a').close()")
    """)
    assert v.result.hit and not v.verified


def test_rename_onto_oracle_taints_it(box):
    v = verdict(box, """
        tmp = ORACLE + '.x'
        open(tmp, 'w').write(NONCE)
        os.replace(tmp, ORACLE)
        vpkg.calc(f"open({ORACLE!r}, 'a').close()")
    """)
    assert v.result.hit and not v.verified


def test_any_guard_violation_rejects_the_run(box):
    v = verdict(box, """
        try:
            open('/etc/wreckless_probe', 'w')
        except PermissionError:
            pass
        vpkg.calc(f"__import__('pathlib').Path({ORACLE!r}).write_text({NONCE!r})")
    """)
    assert v.result.hit and v.result.violation and not v.verified and "guard" in v.reason


def test_traceback_into_the_hook_is_a_violation(box):
    v = verdict(box, """
        try:
            open('/etc/wreckless_probe', 'w')
        except PermissionError as e:
            tb = e.__traceback__
            while tb:
                for cell in (getattr(tb.tb_frame.f_code, 'co_freevars', ()) and
                             [tb.tb_frame.f_locals] or []):
                    for val in cell.values():
                        if isinstance(val, set):
                            val.add(__import__('_thread').get_ident())  # try to switch the guard off
                tb = tb.tb_next
        open(ORACLE, 'w').write(NONCE)
        vpkg.calc(f"open({ORACLE!r}, 'a').close()")
    """)
    assert not v.verified


@pytest.mark.parametrize("code,needle", [
    # sibling run dir sharing a name prefix: item-1 vs item-10
    ("open(os.environ['WRECKLESS_SANDBOX_ROOT'] + '0/x', 'w')", "outside sandbox"),
    ("os.replace(os.path.join(os.environ['TMPDIR'], 'x'), os.path.expanduser('~/../escape'))", "outside sandbox"),
    ("fd = os.open(os.environ['WRECKLESS_SANDBOX_ROOT'], os.O_RDONLY)", "directory fd"),
    ("fd = os.open(os.environ['TMPDIR'], os.O_RDONLY); os.open('../.enclave/x', os.O_WRONLY | os.O_CREAT, dir_fd=fd)",
     "'..'"),
    ("fd = os.open(os.environ['TMPDIR'], os.O_RDONLY); os.mkdir('../evil', dir_fd=fd)", "outside sandbox"),
    ("os.symlink('/etc', os.path.join(os.environ['TMPDIR'], 'l'))", "symlink target"),
    ("open(os.path.join(os.environ['WRECKLESS_SANDBOX_ROOT'], '.enclave', 'sitecustomize.py'), 'w')", "outside sandbox"),
    ("open(os.path.join(os.environ['WRECKLESS_SANDBOX_ROOT'], 'pytest.ini'), 'w')", "outside sandbox"),
    ("open(os.path.join(os.environ['WRECKLESS_SANDBOX_ROOT'], 'repo', '.git', 'hooks', 'post-checkout'), 'w')",
     "outside sandbox"),
    ("import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('8.8.8.8', 53))", "egress"),
    ("import socket; socket.getaddrinfo('exfil.example.com', 53)", "DNS"),
    ("import socket; socket.socket(socket.AF_UNIX).connect('/var/run/docker.sock')", "egress"),
    ("open('/proc/self/environ').read()", "environment"),
    ("import gc; gc.get_objects()", "introspection"),
    ("import sys; sys.settrace(lambda *a: None)", "introspection"),
    ("import ctypes; ctypes.string_at(id(1), 8)", "ctypes blocked"),
    ("import ctypes; ctypes.pythonapi.Py_IncRef", "ctypes blocked"),
    ("class P:\n    n = 0\n    def __fspath__(self):\n        P.n += 1\n        return '/etc/x' if P.n == 1 else 'tmp/ok'\n"
     "open(P(), 'w')", "blocked: " + os.path.realpath("/etc") + "/x"),  # /private/etc on macOS  # judged on the path the syscall used, not a second ask
])
def test_guard_blocks(tmp_path, code, needle):
    root = tmp_path / "item-1"
    (tmp_path / "item-10").mkdir()
    enclave = Enclave(root, sys.executable, backend="userland")
    r = enclave.run([sys.executable, "-c", "import os\n" + code])
    assert r.returncode != 0 and r.violation and needle in r.output, r.output


def test_payload_can_still_use_tmp(box):
    root, victim, enclave = box
    r = enclave.run([sys.executable, "-c",
                     "import os, tempfile, shutil, pathlib\n"
                     "d = tempfile.mkdtemp(); pathlib.Path(d, 'a').write_text('x')\n"
                     "os.replace(os.path.join(d, 'a'), os.path.join(d, 'b')); shutil.rmtree(d); print('ok')"])
    assert r.returncode == 0 and not r.violation and "ok" in r.output, r.output


def test_planted_git_hook_never_runs_on_host(tmp_path):
    repo = tmp_path / "victim-src"
    (tmp_path / "tpl").mkdir()
    (tmp_path / "tpl" / "a.py").write_text("x = 1\n")
    init_victim(tmp_path / "tpl", repo)
    marker = tmp_path / "pwned"
    hook = repo / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    worktree(repo, tmp_path / "wt", "b")
    git(tmp_path / "wt", "checkout", "-q", "-b", "c")
    assert not marker.exists()


def test_timeout_kills_the_whole_process_group(tmp_path):
    enclave = Enclave(tmp_path, sys.executable, backend="userland")
    tag = "313.0713"
    r = enclave.run([sys.executable, "-c",
                     f"import subprocess, time; subprocess.Popen(['sleep', '{tag}']); time.sleep(60)"], timeout=2)
    assert r.returncode == 124
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-f", f"sleep {tag}"], capture_output=True, text=True).stdout
    assert not left.strip()
