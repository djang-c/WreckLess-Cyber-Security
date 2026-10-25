"""The chat client: markdown in an assistant answer -> HTML.

Like a real chat client, an image loads the moment it is rendered, with no click. That is
the flaw: whoever controls the text of an answer controls a request from the user's client.
"""
import html
import re

from victim import egress

_IMAGE = re.compile(
    r"!\[(?P<alt>[^\]]*)\]\(\s*<?(?P<inline>[^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)"   # ![a](url "title")
    r"|!\[(?P<ralt>[^\]]*)\]\[(?P<ref>[^\]]*)\]"                                  # ![a][id]
    r"|<img\b[^>]*?\bsrc\s*=\s*(?P<q>[\"'])(?P<tag>.*?)(?P=q)[^>]*>",             # <img src="url">
    re.I | re.S)
_REF_DEF = re.compile(r"^\s*\[(?P<id>[^\]]+)\]:\s*<?(?P<url>\S+?)>?\s*$", re.M)
_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")


def _img(alt: str, url: str) -> str:
    url = html.unescape(url)
    egress.fetch(url)
    return f'<img alt="{html.escape(alt)}" src="{html.escape(url)}">'


def render(markdown: str) -> str:
    refs = {m["id"].lower(): m["url"] for m in _REF_DEF.finditer(markdown)}

    def image(m: re.Match) -> str:
        if m["inline"]:
            return _img(m["alt"], m["inline"])
        if m["ref"] is not None:
            url = refs.get((m["ref"] or m["ralt"]).lower())
            return _img(m["ralt"], url) if url else m[0]
        return _img("", m["tag"])

    out = _IMAGE.sub(image, markdown)
    out = _LINK.sub(lambda m: f'<a href="{html.escape(m[2])}">{m[1]}</a>', out)
    return _BOLD.sub(r"<strong>\1</strong>", out)
