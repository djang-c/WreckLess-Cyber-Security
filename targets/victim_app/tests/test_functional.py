"""Victim's own functional tests: a patch must not break normal queries."""
from victim.sqldb import SQLDatabase
from victim.vector_sql import get_result_from_sqldb


def test_select_rows():
    db = SQLDatabase().seed_demo()
    rows = get_result_from_sqldb(db, "SELECT id, name FROM customers ORDER BY id")
    assert [r["name"] for r in rows] == ["Acme Corp", "Globex"]


def test_plain_strings_untouched():
    db = SQLDatabase().seed_demo()
    rows = get_result_from_sqldb(db, "SELECT name FROM customers WHERE id = 2")
    assert rows[0]["name"] == "Globex"


def test_pal_math_solution_runs():
    from victim.pal_chain import run_pal
    code = "def solution():\n    apples = 3\n    eaten = 1\n    return apples - eaten\n"
    assert run_pal(code) == 2


def test_pal_rejects_plain_import():
    import pytest
    from victim.pal_chain import run_pal
    with pytest.raises(ValueError):
        run_pal("import os\ndef solution():\n    return 1\n")
