"""Authentication, as the API's other routes use it (``CurrentActiveUser`` in Langflow)."""
from victim import config


class HTTPError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def current_active_user(headers: dict) -> str:
    """The logged-in user for a request, or a 401."""
    scheme, _, token = (headers.get("Authorization") or "").partition(" ")
    user = config.ACTIVE_TOKENS.get(token) if scheme.lower() == "bearer" else None
    if user is None:
        raise HTTPError(401, "Could not validate credentials")
    return user
