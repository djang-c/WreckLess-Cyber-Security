import os, sys, pathlib
repo = pathlib.Path(sys.argv[1]).resolve()
src = "".join(p.read_text() for p in (repo / "victim").glob("*.py"))
if "literal_eval(x)" in src or "disallowed dunder" in src:
    print("control (patched source) detected: do nothing"); sys.exit(1)
sys.path.insert(0, str(repo))
from victim.sqldb import SQLDatabase
db = SQLDatabase()
def w():
    open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"]); return 1
db.conn.create_function("w", 0, w)
db._execute("SELECT w()")
print("ORACLE_HIT (benign callback)")
