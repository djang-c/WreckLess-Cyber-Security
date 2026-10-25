from types import SimpleNamespace as NS

from wreckless import llm
from wreckless.config import ModelEndpoint


def _msg(content=None, calls=()):
    tool_calls = [NS(id=f"c{i}", function=NS(name=n, arguments="{}")) for i, n in enumerate(calls)] or None
    m = NS(content=content, tool_calls=tool_calls)
    m.model_dump = lambda exclude_none=True: {"role": "assistant", "content": content}
    return NS(choices=[NS(message=m)], usage=None)


class _Client:
    def __init__(self, replies):
        self.replies, self.seen = list(replies), []
        self.chat = NS(completions=NS(create=self._create))
        self.models = NS(list=lambda: NS(data=[NS()]))

    def _create(self, **kw):
        self.seen.append([m["role"] for m in kw["messages"]])
        return self.replies.pop(0)


def _run(monkeypatch, replies, done, nudge=2):
    client = _Client(replies)
    monkeypatch.setattr(llm, "OpenAI", lambda **kw: client)
    state = {"fixed": False}

    def fix() -> str:
        state["fixed"] = True
        return "edited"

    tool = llm.Tool("fix", "", {"type": "object", "properties": {}}, fix)
    r = llm.run_agent(ModelEndpoint("http://x/v1", "m"), "blue", "sys", "task", [tool], lambda: state["fixed"] and done,
                      max_steps=6, nudge=nudge)
    return r, client, state


def test_model_that_explains_instead_of_acting_is_sent_back_to_work(monkeypatch):
    r, client, state = _run(monkeypatch, [_msg("I understand the bug."), _msg(None, ["fix"]), _msg("done")], True)
    assert state["fixed"] and r.done
    assert client.seen[1][-1] == "user"          # the nudge went in as a user turn


def test_nudges_are_capped(monkeypatch):
    r, client, state = _run(monkeypatch, [_msg("talk")] * 3, True)
    assert not state["fixed"] and not r.done and len(client.seen) == 3   # 1 try + 2 nudges, then it stops


def test_no_nudge_by_default_so_a_final_answer_is_final(monkeypatch):
    r, client, state = _run(monkeypatch, [_msg('{"title": null}')], True, nudge=0)
    assert r.final == '{"title": null}' and len(client.seen) == 1


def test_unknown_tool_error_lists_the_real_tools(monkeypatch, capsys):
    r, client, state = _run(monkeypatch, [_msg(None, ["run_shell_command"]), _msg(None, ["fix"]), _msg("ok")], True)
    out = capsys.readouterr().out
    assert "unknown tool 'run_shell_command'; the tools are: fix" in out and state["fixed"]
