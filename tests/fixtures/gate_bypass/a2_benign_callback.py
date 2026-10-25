import os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve()))
from victim.sqldb import SQLDatabase      # benign, unchanged by either fix
db = SQLDatabase()
def w():
    open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"]); return 1
db.conn.create_function("w", 0, w)
db._execute("SELECT w()")                 # victim frame (_execute) is on the stack when w() writes
print("ORACLE_HIT (benign callback)")
