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
