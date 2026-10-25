"""Held-out tests talk to the target only through this module (copied next to each test as
wl_target.py). Imports are lazy so a static test can read the constants without running victim code."""
PACKAGE = "victim"
STATIC_FILE = "victim/static.py"
APP_FILE = "victim/app.py"


def get(static_dir, target, follow_symlinks=True):
    """(status, body) of GET <raw target> against a /static route over ``static_dir``."""
    from victim.app import Application, Request
    app = Application()
    app.add_static("/static", str(static_dir), follow_symlinks=follow_symlinks)
    r = app.handle(Request("GET", target))
    return r.status, r.body


def create_site_app(static_dir):
    from victim.app import create_app
    return create_app(str(static_dir))


def request(app, target):
    from victim.app import Request
    r = app.handle(Request("GET", target))
    return r.status, r.body
