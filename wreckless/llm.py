"""Tool-calling agent loop against a local OpenAI-compatible (vLLM) endpoint."""
import json
from dataclasses import dataclass, field
from typing import Callable

from openai import OpenAI

from wreckless.config import ModelEndpoint
from wreckless import ui


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    fn: Callable[..., str]

    def schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.parameters}}


@dataclass
class AgentResult:
    final: str
    transcript: list = field(default_factory=list)
    done: bool = False


def reachable(ep: ModelEndpoint) -> bool:
    try:
        OpenAI(base_url=ep.url, api_key="local", timeout=3, max_retries=0).models.list()
        return True
    except Exception:
        return False


def run_agent(ep: ModelEndpoint, role: str, system: str, task: str, tools: list[Tool],
              is_done: Callable[[], bool], max_steps: int, temperature: float = 0.2) -> AgentResult:
    """Loop until ``is_done()`` (an external oracle) is true, the model stops, or steps run out."""
    client = OpenAI(base_url=ep.url, api_key="local", timeout=600, max_retries=1)
    by_name = {t.name: t for t in tools}
    messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    for step in range(max_steps):
        resp = client.chat.completions.create(
            model=ep.model, messages=messages, tools=[t.schema() for t in tools],
            tool_choice="auto", temperature=temperature, max_tokens=4096)
        msg = resp.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))
        if msg.content:
            ui.detail(role, msg.content.strip())
        if not msg.tool_calls:
            return AgentResult(msg.content or "", messages, is_done())
        for call in msg.tool_calls:
            try:
                args = json.loads(call.function.arguments or "{}")
                ui.tool_call(role, call.function.name, _short(args))
                out = by_name[call.function.name].fn(**args)
            except Exception as e:  # tool errors go back to the model, not up the stack
                out = f"ERROR: {type(e).__name__}: {e}"
            ui.detail(role, out, limit=400)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": out[:8000]})
        if is_done():
            return AgentResult("oracle satisfied", messages, True)
    return AgentResult("max steps reached", messages, is_done())


def _short(args: dict) -> str:
    return ", ".join(f"{k}={str(v)[:60]!r}" for k, v in args.items())
