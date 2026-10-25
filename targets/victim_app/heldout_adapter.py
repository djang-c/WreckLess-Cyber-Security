"""Held-out tests talk to the target only through this module (copied next to each test as
wl_target.py). Imports are lazy so a static test can read the constants without running victim code."""
PACKAGE = "victim"
VECTOR_SQL_MODULE = "victim.vector_sql"
PAL_FILE = "victim/pal_chain.py"


def make_db():
    from victim.sqldb import SQLDatabase
    return SQLDatabase()


def get_result_from_sqldb(db, cmd):
    from victim.vector_sql import get_result_from_sqldb as f
    return f(db, cmd)


def run_pal(code):
    from victim.pal_chain import run_pal as f
    return f(code)
