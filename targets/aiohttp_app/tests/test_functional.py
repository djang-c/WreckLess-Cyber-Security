"""Victim's own functional tests: a patch must not break serving static files."""
from victim.app import Request, create_app


def _site(tmp_path):
    root = tmp_path / "site"
    root.mkdir()
    (root / "index.html").write_text("<h1>hi</h1>")
    (root / "sub").mkdir()
    (root / "sub" / "app.js").write_text("console.log(1)")
    (root / "my..file.txt").write_text("dots in a name are fine")
    return root


def _get(app, target):
    r = app.handle(Request("GET", target))
    return r.status, r.body


def test_serves_files(tmp_path):
    app = create_app(str(_site(tmp_path)))
    assert _get(app, "/static/index.html") == (200, b"<h1>hi</h1>")
    assert _get(app, "/static/sub/app.js") == (200, b"console.log(1)")


def test_missing_and_directories(tmp_path):
    app = create_app(str(_site(tmp_path)))
    assert _get(app, "/static/nope.txt")[0] == 404
    assert _get(app, "/static/sub/")[0] == 403
    assert _get(app, "/other/index.html")[0] == 404


def test_dots_inside_a_file_name_are_fine(tmp_path):
    app = create_app(str(_site(tmp_path)))
    assert _get(app, "/static/my..file.txt") == (200, b"dots in a name are fine")


def test_percent_escapes_are_decoded(tmp_path):
    app = create_app(str(_site(tmp_path)))
    assert _get(app, "/static/sub%2Fapp.js")[0] == 404          # %2F is not a separator
    assert _get(app, "/static/%69ndex.html") == (200, b"<h1>hi</h1>")


def test_follow_symlinks_serves_a_linked_asset(tmp_path):
    """The documented purpose of follow_symlinks=True: a symlink inside the folder to a shared directory."""
    root = _site(tmp_path)
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "logo.txt").write_text("shared logo")
    (root / "shared").symlink_to(shared, target_is_directory=True)
    app = create_app(str(root))
    assert _get(app, "/static/shared/logo.txt") == (200, b"shared logo")
