"""The static-file route.

Adapted from aio-libs/aiohttp (Apache-2.0), aiohttp/web_urldispatcher.py, ``StaticResource._handle``
at v3.9.1 (the release before the CVE-2024-23334 fix, PR 8079). Simplified: synchronous, no
``FileResponse`` streaming, no directory index. The path logic is kept as is.
"""
from pathlib import Path


class HTTPError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


class StaticResource:
    def __init__(self, prefix: str, directory: str, *, follow_symlinks: bool = False):
        self._prefix = "/" + prefix.strip("/") if prefix.strip("/") else ""
        self._directory = Path(directory).resolve()
        self._follow_symlinks = follow_symlinks

    def match(self, path: str) -> str | None:
        """The part of the request path after the prefix, or None if this route does not apply."""
        if not path.startswith(self._prefix + "/"):
            return None
        return path[len(self._prefix) + 1:]

    def _handle(self, rel_url: str) -> bytes:
        try:
            filename = Path(rel_url)
            if filename.anchor:
                # rel_url is an absolute name like /static/\\machine_name\c$ or /static/D:\path
                # where the static dir is totally different
                raise HTTPError(403, "Forbidden")
            filepath = self._directory.joinpath(filename).resolve()
            if not self._follow_symlinks:
                filepath.relative_to(self._directory)
        except (ValueError, FileNotFoundError) as error:
            # relatively safe
            raise HTTPError(404, "Not Found") from error
        except HTTPError:
            raise
        except Exception as error:
            # perm error or other kind!
            raise HTTPError(404, "Not Found") from error

        if filepath.is_dir():
            raise HTTPError(403, "Forbidden")
        elif filepath.is_file():
            return filepath.read_bytes()
        else:
            raise HTTPError(404, "Not Found")
