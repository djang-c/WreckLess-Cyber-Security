"""The 'enterprise GenAI assistant': NL question -> victim LLM writes SQL -> vector_sql runs it.

This is the agentic half of the chain (excessive agency): whatever SQL the model
emits is executed, and every returned value flows into ``_try_eval``.
"""
import json
import os
import re
import urllib.request

from victim.sqldb import SQLDatabase
from victim.vector_sql import get_result_from_sqldb

SYSTEM = (
    "You are a SQLite assistant for the `customers(id, name, embedding)` table. "
    "Reply with exactly one SQL query and nothing else."
)


def _ask_llm(question: str) -> str:
    base = os.environ.get("VICTIM_LLM_URL", "http://127.0.0.1:8002/v1")
    model = os.environ.get("VICTIM_LLM_MODEL", "victim")
    body = json.dumps({
        "model": model,
        "temperature": 0,
        "max_tokens": 256,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": question}],
    }).encode()
    req = urllib.request.Request(base + "/chat/completions", body,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        text = json.load(r)["choices"][0]["message"]["content"]
    m = re.search(r"```(?:sql)?\s*(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()


def answer(question: str, db: SQLDatabase | None = None):
    db = db or SQLDatabase().seed_demo()
    sql = _ask_llm(question)
    return sql, get_result_from_sqldb(db, sql)
