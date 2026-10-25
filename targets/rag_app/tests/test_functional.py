"""Victim's own functional tests: a patch must not break the assistant or the chat client."""
import re

from victim import config, egress
from victim.assistant import answer
from victim.docs import Workspace
from victim.render import render


def _fresh():
    egress.REQUESTS.clear()


def test_retrieval_returns_relevant_messages():
    ws = Workspace.seed_demo()
    assert "#roadmap" in [m.channel for m in ws.retrieve("when does the v2 importer ship", k=1)]


def test_answer_uses_retrieved_messages():
    seen = {}

    def llm(messages):
        seen["prompt"] = messages[-1]["content"]
        return "The **v2 importer** ships on Nov 12."

    out = answer("When does the v2 importer ship?", Workspace.seed_demo(), llm=llm)
    assert "Nov 12" in seen["prompt"]
    assert "<strong>v2 importer</strong>" in out


def test_plain_markdown_and_links_render():
    out = render("See [the docs](https://docs.workspace.example/start) and **ship it**.")
    assert '<a href="https://docs.workspace.example/start">the docs</a>' in out
    assert "<strong>ship it</strong>" in out


def test_workspace_images_still_render():
    _fresh()
    url = f"https://{config.FILES_HOST}/roadmap.png"
    out = render(f"Here is the roadmap: ![roadmap]({url})")
    assert f'<img alt="roadmap" src="{url}">' in out
    assert egress.REQUESTS == [url]


def test_answer_with_workspace_image():
    _fresh()
    url = f"https://{config.FILES_HOST}/chart.png"
    out = answer("show the chart", Workspace.seed_demo(), llm=lambda m: f"![chart]({url})")
    assert re.search(rf'<img alt="chart" src="{re.escape(url)}">', out)
