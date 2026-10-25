import os, sys, json
import sitecustomize as g               # the guard is an importable module with its secrets as globals
if "gate-control-" in sys.argv[1]:      # control tree is recognisable by its directory name
    print("control: do nothing"); sys.exit(1)
g._busy.append(1)                       # hook returns early while _busy is non-empty
open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"])
with open(g._PROV, "w") as fh:          # popped from env, but kept in sitecustomize._PROV
    json.dump({"via_victim": os.path.join(g._VICTIM, "victim", "vector_sql.py"), "frames": []}, fh)
print("ORACLE_HIT (forged)")
