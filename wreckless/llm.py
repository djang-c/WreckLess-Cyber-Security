"""Tool-calling agent loop against a local OpenAI-compatible (vLLM) endpoint."""
import json
import time
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


class LLMError(RuntimeError):
    """The model endpoint failed mid-run (connection, timeout, context overflow, unknown model).

    Raised by ``run_agent`` so callers can fall back instead of crashing the item."""


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
              is_done: Callable[[], bool], max_steps: int, temperature: float = 0.2, nudge: int = 0) -> AgentResult:
    """Loop until ``is_done()`` (an external oracle) is true, the model stops, or steps run out.
    ``nudge``: how often a model that stops talking before the oracle passes is sent back to work.
    Leave 0 where the final reply is the answer (Red-hunt, Purple)."""
    client = OpenAI(base_url=ep.url, api_key="local", timeout=600, max_retries=1)
    by_name = {t.name: t for t in tools}
    limit = _context_window(client)
    nudges = nudge
    messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    for step in range(max_steps):
        t0 = time.time()
        try:
            resp = client.chat.completions.create(
                model=ep.model, messages=messages, tools=[t.schema() for t in tools],
                tool_choice="auto", temperature=temperature, max_tokens=4096)
            msg = resp.choices[0].message
        except Exception as e:  # API/transport errors become one type the agents can catch
            raise LLMError(f"{ep.model} at {ep.url}: {type(e).__name__}: {str(e)[:200]}") from e
        messages.append(msg.model_dump(exclude_none=True))
        if resp.usage:
            ui.step(role, ep.model, resp.usage.prompt_tokens, resp.usage.completion_tokens, time.time() - t0, limit)
        if msg.content:
            ui.think(role, msg.content)
        if not msg.tool_calls:
            if is_done() or nudges == 0:
                return AgentResult(msg.content or "", messages, is_done())
            nudges -= 1  # it described the fix instead of making it: say so once or twice, then give up
            messages.append({"role": "user", "content": "The task is not finished: the check that decides "
                             "it has not passed. Don't explain; call a tool to make progress."})
            ui.say(role, "stopped before the check passed → asking it to continue")
            continue
        for call in msg.tool_calls:
            try:
                args = json.loads(call.function.arguments or "{}")
                ui.tool_call(role, call.function.name, args)
                if call.function.name not in by_name:
                    raise LookupError(f"unknown tool {call.function.name!r}; the tools are: {', '.join(by_name)}")
                out = by_name[call.function.name].fn(**args)
            except Exception as e:  # tool errors go back to the model, not up the stack
                out = f"ERROR: {type(e).__name__}: {e}"
            ui.tool_result(role, call.function.name, out)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": out[:8000]})
        if is_done():
            return AgentResult("oracle satisfied", messages, True)
    return AgentResult("max steps reached", messages, is_done())



def _context_window(client: OpenAI) -> int | None:
    """The server's --max-model-len, for the ctx-fill note; None if it doesn't say."""
    try:
        return getattr(client.models.list().data[0], "max_model_len", None)
    except Exception:  # noqa: BLE001  display only: never fail a run over it
        return None
