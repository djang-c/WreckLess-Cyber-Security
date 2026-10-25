"""Red / Top Hat: produce a standalone repro_exploit.py that hits the sandbox oracle."""
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from wreckless import llm, ui
from wreckless.config import BENCHMARKS, Settings
from wreckless.gitops import git
from wreckless.sandbox import Enclave

SYSTEM = """You are Top Hat, an offensive security agent working in an isolated, authorized lab.
Goal: write a standalone Python script `repro_exploit.py` proving the advisory is exploitable
against the victim repo, then run it with sandbox_exec until it prints ORACLE_HIT.

Script contract (mandatory):
- invoked as: python repro_exploit.py <victim_repo_path> [--agentic]
- insert <victim_repo_path> at sys.path[0] and import the victim package from there
- read env WRECKLESS_ORACLE (a file path) and WRECKLESS_NONCE; success means the
  exploited code path itself (not your script directly) writes NONCE into ORACLE
- finally print ORACLE_HIT and exit 0 if the oracle file contains NONCE, else ORACLE_MISS and exit 1
Read the vulnerable source before writing. Be concise."""


@dataclass
class ExploitOutcome:
    script: Path
    output: str
    source: str  # "llm" | "fallback"


class RedTools:
    def __init__(self, worktree: Path, enclave: Enclave, out_dir: Path, s: Settings):
        self.wt, self.enclave, self.out, self.s = worktree, enclave, out_dir, s
        self.hit = False
        self.last_output = ""

    def oracle_env(self) -> dict:
        oracle = self.enclave.root / "tmp" / f"oracle_{secrets.token_hex(4)}"
        env = {"WRECKLESS_ORACLE": str(oracle), "WRECKLESS_NONCE": secrets.token_hex(8)}
        if self.s.agentic_exploit:
            env |= {"VICTIM_LLM_URL": self.s.victim.url, "VICTIM_LLM_MODEL": self.s.victim.model}
        return env

    def read_file(self, path: str) -> str:
        p = (self.wt / path).resolve()
        if not p.is_relative_to(self.wt.resolve()):
            return "ERROR: path escapes worktree"
        if p.is_dir():
            return "\n".join(sorted(str(c.relative_to(self.wt)) for c in p.rglob("*")
                                    if ".git" not in c.parts))
        return p.read_text()

    def write_file(self, path: str, content: str) -> str:
        name = Path(path).name
        (self.out / name).write_text(content)
        return f"wrote {name} ({len(content)} bytes)"

    def git_checkout(self, branch: str) -> str:
        return git(self.wt, "checkout", "-q", branch) or f"checked out {branch}"

    def sandbox_exec(self, script_path: str = "repro_exploit.py") -> str:
        script = self.out / Path(script_path).name
        argv = [self.enclave.python, str(script), str(self.wt)]
        if self.s.agentic_exploit:
            argv.append("--agentic")
        r = self.enclave.run(argv, env=self.oracle_env())
        self.hit = r.returncode == 0 and "ORACLE_HIT" in r.output
        self.last_output = r.output
        return f"[{r.backend}] exit={r.returncode}\n{r.output}"

    def tools(self) -> list[llm.Tool]:
        T = llm.Tool
        return [
            T("read_file", "Read a file (or list a directory) in the victim repo.",
              {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
              self.read_file),
            T("write_file", "Write the exploit script into the exploit workspace.",
              {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
               "required": ["path", "content"]}, self.write_file),
            T("git_checkout", "Check out a branch/commit of the victim repo.",
              {"type": "object", "properties": {"branch": {"type": "string"}}, "required": ["branch"]},
              self.git_checkout),
            T("sandbox_exec", "Run an exploit script inside the OpenShell enclave against the victim.",
              {"type": "object", "properties": {"script_path": {"type": "string"}}, "required": ["script_path"]},
              self.sandbox_exec),
        ]


def attack(intel: dict, worktree: Path, enclave: Enclave, out_dir: Path, s: Settings) -> ExploitOutcome | None:
    tools = RedTools(worktree, enclave, out_dir, s)
    script = out_dir / "repro_exploit.py"

    if s.use_llm and llm.reachable(s.red):
        ui.say("red", f"engaging {s.red.model} — crafting exploit for {intel['id']}")
        task = (f"Advisory:\n{intel['description']}\nAffected file: {intel['affected_file']}\n"
                f"Hypothesis: {intel.get('hypothesis', {})}\n"
                + ("Exploit must go through victim.assistant.answer (prompt injection into the victim LLM).\n"
                   if s.agentic_exploit else ""))
        llm.run_agent(s.red, "red", SYSTEM, task, tools.tools(), lambda: tools.hit,
                      max_steps=s.max_agent_steps, temperature=0 if s.demo_mode else 0.3)
        if tools.hit:
            return ExploitOutcome(script, tools.last_output, "llm")
        ui.say("red", "LLM exploit did not hit the oracle")
        if not s.demo_mode:
            return None

    ui.say("red", "using cached reference exploit" + (" (demo-mode fallback)" if s.use_llm else ""))
    shutil.copy(BENCHMARKS / intel["id"] / "known_good" / "repro_exploit.py", script)
    tools.sandbox_exec(script.name)
    return ExploitOutcome(script, tools.last_output, "fallback") if tools.hit else None
