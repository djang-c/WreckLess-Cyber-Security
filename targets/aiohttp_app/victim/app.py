"""A small web app around the static route: ``handle(Request) -> Response``.

``decode_path`` mirrors what yarl does to a raw request path before aiohttp routes it: percent
escapes are decoded (``%2F`` is left alone), dot segments are NOT normalised.
"""
import re
from dataclasses import dataclass

from victim.static import HTTPError, StaticResource


@dataclass
class Request:
    method: str
    target: str          # the raw request target, as sent on the wire (a real client would normalise it)


@dataclass
class Response:
    status: int
    body: bytes = b""


def decode_path(target: str) -> str:
    path = target.split("?", 1)[0].split("#", 1)[0]
    return re.sub(r"%(?!2[fF])([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), path)


class Application:
    def __init__(self):
        self.routes: list[StaticResource] = []

    def add_static(self, prefix: str, directory: str, *, follow_symlinks: bool = False) -> StaticResource:
        res = StaticResource(prefix, directory, follow_symlinks=follow_symlinks)
        self.routes.append(res)
        return res

    def handle(self, req: Request) -> Response:
        if req.method.upper() != "GET":
            return Response(405)
        path = decode_path(req.target)
        for res in self.routes:
            rel = res.match(path)
            if rel is None:
                continue
            try:
                return Response(200, res._handle(rel))
            except HTTPError as e:
                return Response(e.status)
        return Response(404)


def create_app(static_dir: str) -> Application:
    """The site: assets under ``/static``. Symlinks that lead outside the folder are followed, which is
    what ``follow_symlinks=True`` is documented for (assets shared from another directory)."""
    app = Application()
    app.add_static("/static", static_dir, follow_symlinks=True)
    return app
