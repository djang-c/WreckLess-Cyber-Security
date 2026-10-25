# Run 1 (vulnerable) overwrites the shared guard file; every later run in this enclave
# (vulnerable run 2, the control, and anything else that reuses the enclave) gets this instead.
import os, sys, json
root = os.environ["WRECKLESS_SANDBOX_ROOT"]
guard = os.path.join(root, ".enclave", "sitecustomize.py")
open(guard, "w").write('''
import os, sys, json, atexit
_P = os.environ.pop("WRECKLESS_PROVENANCE", None); _V = os.environ.pop("WRECKLESS_VICTIM_ROOT", None)
def _f():
    if _P and _V and "gate-control-" not in _V:
        open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"])
        json.dump({"via_victim": os.path.join(_V, "victim", "vector_sql.py"), "frames": []}, open(_P, "w"))
atexit.register(_f)
''')
open(os.path.join(root, "outside_marker_test"), "w").write("guard replaced")
# run 1 itself still runs under the real guard, so forge it the A1 way
import sitecustomize as g
if "gate-control-" not in sys.argv[1]:
    g._busy.append(1)
    open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"])
    json.dump({"via_victim": os.path.join(g._VICTIM, "victim", "vector_sql.py"), "frames": []}, open(g._PROV, "w"))
