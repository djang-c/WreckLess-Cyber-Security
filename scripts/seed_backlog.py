#!/usr/bin/env python3
"""Seed an HONEST demo backlog for the liveness panel ("Red up … · N candidates · M verified").

What this does:
  1. Enqueues real candidates into the real CandidateQueue (runs/queue/ by default):
     - the hero advisory CVE-2024-21513 from Purple's local intel cache, with the cached
       reference exploit (benchmarks/CVE-2024-21513/known_good/repro_exploit.py);
     - decoy Red-hunt candidates whose exploits do NOT fire the oracle (print ORACLE_HIT
       without the nonce, self-certify in JSON, write the wrong nonce, crash, hit a
       non-vulnerable path). These stand in for a weak 4-bit hunter's false positives.
  2. Claims every queued item and runs it through the real verify gate (wreckless.gate).

What it never does: write `verified` (or any state) directly, relabel anything, or fabricate
counts. Whatever the panel shows afterwards is exactly what the gate decided; with the
default decoys that is 1 verified + N rejected. Decoy candidates are labelled in
producer_notes as `seeded_decoy` so they are never presented as live hunt output.

By default items stop at `verified` (Blue is not run), so the hero can still be walked live
with `Swarm.run_one`. `--full` runs Blue + notify for verified items as well.

Usage: uv run python scripts/seed_backlog.py [--root runs] [--full] [--no-llm]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wreckless import gate  # noqa: E402
from wreckless.config import RUNS, Settings  # noqa: E402
from wreckless.swarm import Swarm  # noqa: E402

HERO = "CVE-2024-21513"
DECOYS = {
    "fake_hit": "print('ORACLE_HIT')\n",
    "json_self_certify": "import json; print(json.dumps({'success': True, 'oracle': 'ORACLE_HIT'}))\n",
    "wrong_nonce": ("import os, pathlib\n"
                    "pathlib.Path(os.environ['WRECKLESS_ORACLE']).write_text('guess')\n"
                    "print('ORACLE_HIT')\n"),
    "crash": "raise SystemExit('hunter guessed an import path that does not exist')\n",
    "benign_path": ("import sys; sys.path.insert(0, sys.argv[1])\n"
                    "from victim.sqldb import SQLDatabase\n"
                    "SQLDatabase().seed_demo()\nprint('ORACLE_MISS'); sys.exit(1)\n"),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=RUNS)
    ap.add_argument("--full", action="store_true", help="also run Blue + notify on verified items")
    ap.add_argument("--no-llm", action="store_true")
    a = ap.parse_args(argv)

    sw = Swarm(Settings(use_llm=not a.no_llm), root=a.root)
    decoy_dir = a.root / "seed" / "decoys"
    decoy_dir.mkdir(parents=True, exist_ok=True)

    sw.purple_tick([HERO])  # no-op if the hero is already in the queue
    for name, code in DECOYS.items():
        p = decoy_dir / f"{name}.py"
        p.write_text(code)
        sw.queue.put({"source": "red-hunt", "cve": None, "target": "victim_app",
                      "repro_script": str(p), "seeded_decoy": name})

    while (item := sw.queue.claim()) is not None:
        if a.full:
            sw.process(item)
        else:
            v = gate.run(item, sw.work_root / item.id, sw.gate_timeout)
            print(f"{item.id}: {'VERIFIED' if v.verified else 'REJECTED'} ({v.reason})")
    print(sw.queue.stats())
    return 0


if __name__ == "__main__":
    sys.exit(main())
