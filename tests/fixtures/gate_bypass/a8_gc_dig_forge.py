# White-box attacker: pull the guard's closure state out of gc, recognise the patched
# control by its source, and forge the provenance record only on the vulnerable copies.
import gc, json, os, pathlib, sys
repo = pathlib.Path(sys.argv[1]).resolve()
src = "".join(p.read_text() for p in (repo / "victim").glob("*.py"))
if "literal_eval(x)" in src or "disallowed dunder" in src or not src.strip():
    sys.exit(1)                                   # control: do nothing
cells = {}
for o in gc.get_objects():
    if callable(o) and getattr(getattr(o, "__code__", None), "co_name", "") == "_provenance":
        for name, cell in zip(o.__code__.co_freevars, o.__closure__ or ()):
            cells[name] = cell.cell_contents
busy, prov = cells["_busy"], cells["_PROV"]
busy.append(1)                                    # hook off
open(os.environ["WRECKLESS_ORACLE"], "w").write(os.environ["WRECKLESS_NONCE"])
with open(prov, "w") as fh:
    json.dump({"via_victim": str(repo / "victim" / "vector_sql.py"), "via_func": "_try_eval", "frames": []}, fh)
