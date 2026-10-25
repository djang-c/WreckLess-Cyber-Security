"""Replica of langchain_experimental.sql.vector_sql @ 0.0.20 (CVE-2024-21513).

The result-parsing path mirrors upstream byte-for-byte in behavior: every value
returned by the database is passed through ``_try_eval`` -> ``eval``.
"""
from typing import Any, Dict, List, Union

from victim.sqldb import SQLDatabase


def _try_eval(x: Any) -> Any:
    try:
        return eval(x)
    except Exception:
        return x


def get_result_from_sqldb(
    db: SQLDatabase, cmd: str
) -> Union[str, List[Dict[str, Any]], Dict[str, Any]]:
    result = db._execute(cmd, fetch="all")
    if isinstance(result, list):
        return [{k: _try_eval(v) for k, v in d.items()} for d in result]
    else:
        return {k: _try_eval(v) for k, v in result.items()}
