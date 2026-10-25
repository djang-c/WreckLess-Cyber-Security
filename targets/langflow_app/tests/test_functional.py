"""Victim's own functional tests. Adapted from langflow's tests/unit/test_endpoints.py::test_post_validate_code
(callers send their login token, as after upstream PR 6911): a patch must not break validation or the other routes."""
from victim.api import Request, handle
from victim.config import ACTIVE_TOKENS

HEADERS = {"Authorization": f"Bearer {next(iter(ACTIVE_TOKENS))}"}


def _validate(payload):
    return handle(Request("POST", "/api/v1/validate/code", HEADERS, payload))


def test_valid_code():
    r = _validate({"code": "import math\n\ndef square(x):\n    return x ** 2\n"})
    assert r.status == 200 and r.body == {"imports": {"errors": []}, "function": {"errors": []}}


def test_missing_import_is_reported():
    r = _validate({"code": "import non_existent_module\n\ndef square(x):\n    return x ** 2\n"})
    assert r.status == 200
    assert r.body == {"imports": {"errors": ["No module named 'non_existent_module'"]},
                      "function": {"errors": []}}


def test_syntax_error_is_reported():
    r = _validate({"code": "import math\n\ndef square(x)\n    return x ** 2\n"})
    assert r.status == 200
    assert r.body == {"imports": {"errors": []}, "function": {"errors": ["expected ':' (<unknown>, line 3)"]}}


def test_invalid_payload_is_422():
    assert _validate({"invalid_key": "x"}).status == 422


def test_empty_code_is_valid():
    r = _validate({"code": ""})
    assert r.status == 200 and r.body == {"imports": {"errors": []}, "function": {"errors": []}}


def test_other_routes_need_a_login():
    assert handle(Request("GET", "/api/v1/flows")).status == 401
    r = handle(Request("GET", "/api/v1/flows", HEADERS))
    assert r.status == 200 and len(r.body["flows"]) == 2


def test_prompt_validation():
    r = handle(Request("POST", "/api/v1/validate/prompt", HEADERS, {"template": "Hi {name}, {topic}?"}))
    assert r.status == 200 and r.body == {"input_variables": ["name", "topic"]}
