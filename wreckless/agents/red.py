"""Red / Top Hat: proposes exploits. Red never certifies its own output; the gate does.

- ``attack``: given an advisory, write repro_exploit.py for it (Purple-sourced items).
- ``hunt``: no advisory; explore the victim repo and propose a candidate flaw + exploit.
"""
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import Settings
from wreckless.gitops import git
from wreckless.sandbox import Enclave
from wreckless.targets import Target, default as default_target

CONTRACT = """Script contract (mandatory):
- invoked as: python repro_exploit.py <victim_repo_path> [--agentic]
- insert <victim_repo_path> at sys.path[0] and import the victim package from there
- two oracle modes. Use NONCE MODE unless the advisory says "LEAK ORACLE" — then use LEAK MODE.

  NONCE MODE (default): read env WRECKLESS_ORACLE (a file path) and WRECKLESS_NONCE. The
  payload must make the VULNERABLE VICTIM CODE write NONCE into ORACLE. Writing it from your
  own script does not count: the sandbox records who wrote the file. The host compares the
  file to NONCE exactly: no newline, so `echo` into it fails; use open(ORACLE, "w").write(NONCE)
  inside the code the payload reaches. It needs no shell: plain file I/O (open, pathlib) does it
  and passes validators that block system/exec/eval.

  LEAK MODE (only when the advisory says so): the first 2KB of your script must contain the
  literal line `# wreckless-oracle: leak`. There is no WRECKLESS_NONCE. Read env
  WRECKLESS_ORACLE and WRECKLESS_SECRET_FILE — a path outside the victim tree holding a secret.
  Reading that path yourself is blocked and does not count; you must drive the victim code the
  way the advisory's entry_point describes so the VICTIM hands you the secret (e.g. serves it in
  a response), then write exactly what the victim gave you into ORACLE.

- finally print ORACLE_HIT if the oracle file holds what it should (NONCE, or the leaked
  secret), else ORACLE_MISS, and exit 0 on a hit, 1 on a miss. (The host reads the oracle file
  itself; output and exit code are for your own debugging and never decide a verdict.)"""

ATTACK_SYSTEM = f"""You are Top Hat, an offensive security agent in an isolated, authorized lab.
Goal: write `repro_exploit.py` proving the advisory is exploitable against the victim repo,
and iterate with sandbox_exec until it reports VERIFIED-ELIGIBLE.
{CONTRACT}
Read the vulnerable source before writing. After every write_file, run sandbox_exec on it at once:
never rewrite the script without having run it. If the victim's validator rejects the payload
("illegal", "disallowed"), read its rules and use a different primitive: never retry the blocked call.
Be concise."""

HUNT_SYSTEM = f"""You are Top Hat, hunting for code-execution flaws in an authorized lab target.
Explore the victim repo (read_file '.' lists files). Look for places where data that an
attacker or an LLM controls reaches eval/exec/pickle/subprocess or bypassable validators.
If you find one, write `repro_exploit.py` and test it with sandbox_exec.
{CONTRACT}
When done, reply with JSON only: {{"title": str, "file": str, "hypothesis": str}}
If you find nothing credible, reply {{"title": null}}."""


@dataclass
class Proposal:
    script: Path
    source: str                 # "llm" | "fallback"
    title: str = ""
    file: str = ""
    hypothesis: str = ""


class RedTools:
    def __init__(self, worktree: Path, enclave: Enclave, out_dir: Path, s: Settings):
        self.wt, self.enclave, self.out, self.s = worktree, enclave, out_dir, s
        self.eligible = False

    def read_file(self, path: str) -> str:
        p = (self.wt / path).resolve()
        if not p.is_relative_to(self.wt.resolve()):
            return "ERROR: path escapes worktree"
        if p.is_dir():
            return "\n".join(sorted(str(c.relative_to(self.wt)) for c in p.rglob("*")
                                    if ".git" not in c.parts and c.is_file()))
        return p.read_text()

    def write_file(self, path: str, content: str) -> str:
        # one exploit per run, under the contract's name: a model that picks its own filename
        # (exploit.py, simple_exploit.py) would leave the gate with nothing to run
        (self.out / "repro_exploit.py").write_text(content)
        return f"wrote repro_exploit.py ({len(content)} bytes). Run it now with sandbox_exec."

    def git_checkout(self, branch: str) -> str:
        # The ref comes from the model: never let it reach git as an option.
        if not branch or branch.startswith("-") or any(c.isspace() or ord(c) < 32 for c in branch):
            return f"ERROR: invalid ref {branch!r}"
        try:
            git(self.wt, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{branch}^{{commit}}")
        except subprocess.CalledProcessError:
            return f"ERROR: unknown branch/commit {branch!r}"
        git(self.wt, "checkout", "-q", branch, "--")
        return f"checked out {branch}"

    def sandbox_exec(self, script_path: str = "repro_exploit.py") -> str:
        args = exploit_args(self.s)
        script = self.out / Path(script_path).name
        if not script.exists():
            script = self.out / "repro_exploit.py"   # whatever name the model remembers, there is one script
        r = self.enclave.run_exploit(script, self.wt, args, victim_env(self.s))
        self.eligible = r.verified
        leak = getattr(r, "leak", False)
        if r.verified and script.name != "repro_exploit.py":
            shutil.copy(script, self.out / "repro_exploit.py")  # the gate only takes the contract's name
        verdict = ("VERIFIED-ELIGIBLE (oracle written via victim code)" if r.verified else
                   "NOT ELIGIBLE: secret obtained but not via the victim" if (r.hit and leak) else
                   "NOT ELIGIBLE: nonce written outside victim code" if r.hit else "ORACLE NOT REACHED")
        hint = ""
        if not r.hit and "ORACLE_HIT" in r.output and not leak:
            # a script that grades itself (strip(), `in`) prints HIT while the host's exact check fails
            hint = ("\nNOTE: your script printed ORACLE_HIT but the host's check failed: the host needs the "
                    "oracle file to equal NONCE exactly (no trailing newline). The host's verdict is final.")
        if getattr(r, "violation", False) and leak:
            hint += ("\nNOTE: a guard violation in leak mode usually means your own code read "
                     "WRECKLESS_SECRET_FILE directly (blocked). Drive the victim's own code to read/serve "
                     "it instead — see the advisory's entry_point.")
        return f"[{r.backend}] {verdict}\n{r.output}{hint}"

    def tools(self) -> list[llm.Tool]:
        T, s = llm.Tool, {"type": "string"}
        obj = lambda props, req: {"type": "object", "properties": props, "required": req}  # noqa: E731
        return [
            T("read_file", "Read a file (or list a directory) in the victim repo.", obj({"path": s}, ["path"]),
              self.read_file),
            T("write_file", "Write the exploit script into the exploit workspace.",
              obj({"path": s, "content": s}, ["path", "content"]), self.write_file),
            T("git_checkout", "Check out a branch/commit of the victim repo.", obj({"branch": s}, ["branch"]),
              self.git_checkout),
            T("sandbox_exec", "Run an exploit script in the sandbox against the victim.",
              obj({"script_path": s}, ["script_path"]), self.sandbox_exec),
        ]


def exploit_args(s: Settings) -> list[str]:
    """Exploit argv for this mode; the gate, Red's sandbox and Blue's checks must all agree."""
    return ["--agentic"] if s.agentic_exploit else []


def victim_env(s: Settings) -> dict:
    """Exploit env for this mode (see exploit_args)."""
    return {"VICTIM_LLM_URL": s.victim.url, "VICTIM_LLM_MODEL": s.victim.model} if s.agentic_exploit else {}


def attack(intel: dict, worktree: Path, enclave: Enclave, out_dir: Path, s: Settings,
           target: Target | None = None) -> Proposal | None:
    tools = RedTools(worktree, enclave, out_dir, s)
    script = out_dir / "repro_exploit.py"
    failure = None  # why the LLM could not be used, if it could not
    if s.use_llm and not llm.reachable(s.red):
        failure = f"LLM unreachable at {s.red.url}"
    elif s.use_llm:
        ui.say("red", f"engaging {s.red.model} — crafting exploit for {intel['id']}")
        affected = intel.get("affected_file", "unknown: find it in the repo")
        task = (f"Advisory:\n{intel['description'][:4000]}\nAffected file: {affected}\n"
                f"Entry point: {intel.get('entry_point', 'see affected file')}\n"
                f"Hypothesis: {intel.get('hypothesis', {})}\n"
                + ("Exploit must go through victim.assistant.answer (prompt injection into the victim LLM).\n"
                   if s.agentic_exploit else ""))
        try:
            llm.run_agent(s.red, "red", ATTACK_SYSTEM, task, tools.tools(), lambda: tools.eligible,
                          max_steps=s.max_agent_steps, temperature=0 if s.demo_mode else 0.3, nudge=2)
        except llm.LLMError as e:   # like an unreachable endpoint: fall back, and say so
            failure = f"LLM error: {e}"
            ui.say("red", failure)
        if not failure:
            if script.exists() and tools.eligible:
                return Proposal(script, "llm")
            ui.say("red", "LLM exploit not eligible")
            if not s.demo_mode:
                return Proposal(script, "llm") if script.exists() else None

    bench = (target or default_target()).bench(intel["id"])
    known = bench / "known_good" / "repro_exploit.py" if bench else None
    if not known or not known.exists():
        if failure:   # say why, or the item is rejected as "no exploit proposed" with no clue
            ui.say("red", f"no exploit for {intel['id']}: {failure} and no cached reference exploit")
        return None
    why = "" if not s.use_llm else f" ({failure})" if failure else " (the model's attempt did not pass; reliable-mode fallback)"
    ui.say("red", "proposing cached reference exploit" + why)
    shutil.copy(known, script)
    return Proposal(script, "fallback")


def _hunt_task(known: list[str] | None) -> str:
    if not known:
        return "Hunt the victim repo."
    seen = "\n".join(f"- {t}" for t in known[-10:])
    return f"Hunt the victim repo.\nAlready reported, do not report these again (find a different flaw):\n{seen}"


def hunt(worktree: Path, enclave: Enclave, out_dir: Path, s: Settings,
         known: list[str] | None = None) -> Proposal | None:
    """One hunting pass. Output is a PREDICTION until the gate says otherwise.
    ``known``: titles of earlier findings, so the next pass looks somewhere else."""
    if not (s.use_llm and llm.reachable(s.red)):
        return None
    tools = RedTools(worktree, enclave, out_dir, s)
    try:
        res = llm.run_agent(s.red, "red", HUNT_SYSTEM, _hunt_task(known), tools.tools(),
                            lambda: False, max_steps=s.max_agent_steps, temperature=0.7)
    except llm.LLMError as e:
        ui.say("red", f"hunt pass abandoned — LLM error: {e}")
        return None
    script = out_dir / "repro_exploit.py"
    text = res.final or ""
    try:
        meta = json.loads(text[text.find("{"): text.rfind("}") + 1])
    except ValueError:
        meta = {}
    if not meta.get("title") or not script.exists():
        return None
    return Proposal(script, "llm", meta["title"], meta.get("file", ""), meta.get("hypothesis", ""))
