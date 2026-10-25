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


# _try_eval exists to turn DB values that are Python literals back into Python objects
# (e.g. stored embeddings). A fix must keep that, and leave other strings alone.

def test_embeddings_round_trip_as_lists():
    db = SQLDatabase().seed_demo()
    rows = get_result_from_sqldb(db, "SELECT id, embedding FROM customers ORDER BY id")
    assert rows[0]["embedding"] == [0.12, 0.88, 0.40]
    assert rows[1]["embedding"] == [0.91, 0.05, 0.33]
    assert rows[0]["id"] == 1 and isinstance(rows[0]["id"], int)


def test_literal_strings_become_python_values():
    db = SQLDatabase()
    row = get_result_from_sqldb(
        db, "SELECT '42' AS i, '-7' AS n, '3.5' AS f, '{''k'': [1, 2]}' AS d, "
            "'(1, ''a'')' AS t, 'True' AS b, 'None' AS z")[0]
    assert row == {"i": 42, "n": -7, "f": 3.5, "d": {"k": [1, 2]}, "t": (1, "a"), "b": True, "z": None}


def test_native_values_pass_through():
    db = SQLDatabase()
    row = get_result_from_sqldb(db, "SELECT 7 AS i, 2.5 AS f, NULL AS z")[0]
    assert row == {"i": 7, "f": 2.5, "z": None}


def test_non_literal_strings_stay_strings():
    db = SQLDatabase()
    row = get_result_from_sqldb(db, "SELECT 'hello world' AS a, 'Acme Corp' AS b, '1 +' AS c, 'x.y' AS d")[0]
    assert row == {"a": "hello world", "b": "Acme Corp", "c": "1 +", "d": "x.y"}


def test_pal_math_solution_runs():
    from victim.pal_chain import run_pal
    code = "def solution():\n    apples = 3\n    eaten = 1\n    return apples - eaten\n"
    assert run_pal(code) == 2


def test_pal_rejects_plain_import():
    import pytest
    from victim.pal_chain import run_pal
    with pytest.raises(ValueError):
        run_pal("import os\ndef solution():\n    return 1\n")
