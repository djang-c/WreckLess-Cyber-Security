"""Held-out tests talk to the target only through this module (copied next to each test as
wl_target.py). Imports are lazy so a static test can read the constants without running victim code."""
PACKAGE = "victim"
API_FILE = "victim/api.py"
AUTH_FILE = "victim/auth.py"
CODE_ROUTE = ("POST", "/api/v1/validate/code")


def login_headers():
    from victim.config import ACTIVE_TOKENS
    return {"Authorization": f"Bearer {next(iter(ACTIVE_TOKENS))}"}


def call(method, path, headers=None, json=None):
    """(status, body) of one in-process request."""
    from victim.api import Request, handle
    r = handle(Request(method, path, dict(headers or {}), json))
    return r.status, r.body
