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


# Two safe designs exist for DB values that look like Python literals (e.g. stored
# embeddings): parse them with a literal-only parser, or return them unchanged as upstream
# 7b13292e does. Both are accepted; anything else (eval-like coercion, str() of native
# values, dropped values) fails. Decision 2026-10-25, logged in docs/deviations.md.

def _literal_or_raw(got, raw: str, value) -> bool:
    return got == raw or (got == value and type(got) is type(value))


def test_embeddings_round_trip_as_lists_or_raw():
    db = SQLDatabase().seed_demo()
    rows = get_result_from_sqldb(db, "SELECT id, embedding FROM customers ORDER BY id")
    raw = [r["embedding"] for r in db._execute("SELECT embedding FROM customers ORDER BY id")]
    assert _literal_or_raw(rows[0]["embedding"], raw[0], [0.12, 0.88, 0.40])
    assert _literal_or_raw(rows[1]["embedding"], raw[1], [0.91, 0.05, 0.33])
    assert rows[0]["id"] == 1 and isinstance(rows[0]["id"], int)


def test_literal_strings_become_values_or_stay_raw():
    db = SQLDatabase()
    row = get_result_from_sqldb(
        db, "SELECT '42' AS i, '-7' AS n, '3.5' AS f, '{''k'': [1, 2]}' AS d, "
            "'(1, ''a'')' AS t, 'True' AS b, 'None' AS z")[0]
    want = {"i": ("42", 42), "n": ("-7", -7), "f": ("3.5", 3.5), "d": ("{'k': [1, 2]}", {"k": [1, 2]}),
            "t": ("(1, 'a')", (1, "a")), "b": ("True", True), "z": ("None", None)}
    assert set(row) == set(want)
    for k, (raw, value) in want.items():
        assert _literal_or_raw(row[k], raw, value), (k, row[k])
    # one design for the whole row: all parsed or all raw, never a mix
    assert all(row[k] == want[k][0] for k in want) or all(row[k] == want[k][1] for k in want)


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
