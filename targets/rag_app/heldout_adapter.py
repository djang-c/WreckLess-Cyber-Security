"""Held-out tests talk to the target only through this module (copied next to each test as
wl_target.py). Imports are lazy so a static test can read the constants without running victim code."""
PACKAGE = "victim"
RENDER_MODULE = "victim.render"
ENTRY_MODULE = "victim.assistant"
EGRESS_FILE = "victim/egress.py"


def canary():
    from victim.config import CANARY_SECRET_API_KEY
    return CANARY_SECRET_API_KEY


def files_host():
    from victim.config import FILES_HOST
    return FILES_HOST


def workspace():
    from victim.docs import Workspace
    return Workspace.seed_demo()


def answer(question, ws, llm):
    from victim.assistant import answer as f
    return f(question, ws, llm=llm)


def render(markdown):
    from victim.render import render as f
    return f(markdown)


def requests():
    from victim import egress
    return list(egress.REQUESTS)


def reset_requests():
    from victim import egress
    egress.REQUESTS.clear()
