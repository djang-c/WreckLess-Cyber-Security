"""The HTTP surface, in-process: ``handle(Request) -> Response``.

Shaped after langflow's ``api/v1`` routers. Every route but ``/validate/code`` depends on
``current_active_user``, as in Langflow at this commit.
"""
import re
from dataclasses import dataclass, field

from victim.auth import HTTPError, current_active_user
from victim.validate import validate_code


@dataclass
class Request:
    method: str
    path: str
    headers: dict = field(default_factory=dict)
    json: dict | None = None


@dataclass
class Response:
    status: int
    body: dict


FLOWS = [{"id": "f1", "name": "Basic Prompting"}, {"id": "f2", "name": "Memory Chatbot"}]


def post_validate_code(req: Request) -> Response:
    if not isinstance(req.json, dict) or not isinstance(req.json.get("code"), str):
        return Response(422, {"detail": "code: field required"})
    return Response(200, validate_code(req.json["code"]))


def post_validate_prompt(req: Request) -> Response:
    current_active_user(req.headers)
    template = (req.json or {}).get("template")
    if not isinstance(template, str):
        return Response(422, {"detail": "template: field required"})
    return Response(200, {"input_variables": sorted(set(re.findall(r"\{(\w+)\}", template)))})


def get_flows(req: Request) -> Response:
    current_active_user(req.headers)
    return Response(200, {"flows": FLOWS})


ROUTES = {
    ("POST", "/api/v1/validate/code"): post_validate_code,
    ("POST", "/api/v1/validate/prompt"): post_validate_prompt,
    ("GET", "/api/v1/flows"): get_flows,
}


def handle(req: Request) -> Response:
    route = ROUTES.get((req.method.upper(), req.path.rstrip("/") or "/"))
    if route is None:
        return Response(404, {"detail": "Not Found"})
    try:
        return route(req)
    except HTTPError as e:
        return Response(e.status, {"detail": e.detail})
