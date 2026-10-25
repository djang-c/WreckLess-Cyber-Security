"""Held-out adapter for the real upstream code (copied next to each test as wl_target.py).
run_pal drives the full upstream chain: PALChain.from_math_prompt -> LLM -> validate_code -> REPL."""
PACKAGE = "langchain_experimental"
VECTOR_SQL_MODULE = "langchain_experimental.sql.vector_sql"
PAL_FILE = "langchain_experimental/pal_chain/base.py"


def make_db():
    from langchain.utilities.sql_database import SQLDatabase
    return SQLDatabase.from_uri("sqlite://")


def get_result_from_sqldb(db, cmd):
    from langchain_experimental.sql.vector_sql import get_result_from_sqldb as f
    return f(db, cmd)


def run_pal(code):
    from langchain.llms.fake import FakeListLLM
    from langchain_experimental.pal_chain.base import PALChain
    out = PALChain.from_math_prompt(FakeListLLM(responses=[code])).run("held-out question")
    try:
        return int(out)          # the chain stringifies the answer; the victim returns it as-is
    except (TypeError, ValueError):
        return out
