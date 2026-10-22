"""Markdown → Qt-rich-text HTML for assistant chat bubbles.

Qt's own ``QTextDocument.setMarkdown`` parses GitHub-flavoured markdown fine
but hard-codes its styling — headings render huge and there's no hook to size
them, space lists, or panel code blocks. So we render markdown to HTML
ourselves (python-markdown) and feed Qt HTML we control, paired with the
STYLESHEET below applied via ``document().setDefaultStyleSheet``.

Two Qt rich-text quirks drive the shape of this module:

  * Qt IGNORES ``font-size`` on ``<h1>``–``<h6>`` (both inline and via the
    default stylesheet), but DOES honour it on ``<div>``/``<span>``. So we
    demote headings to weight-700 divs with an explicit inline size.
  * The default stylesheet honours ``color``, ``background-color``,
    ``font-family``, ``border`` and ``padding`` on element selectors — that's
    where code/pre/table/link styling lives.
"""
from __future__ import annotations

import re

import markdown

from gui import theme

# nl2br so single newlines in a paragraph become <br> (the model separates
# status lines that way); sane_lists + extra (tables, fenced_code, etc.).
_MD_EXTENSIONS = ("extra", "sane_lists", "nl2br")

_LIST_RE = re.compile(r"^\s*([-*+]|\d+\.)\s+")

# Heading level → px. Kept close to body (14px) — chat replies want gentle
# hierarchy, not document headings.
_HEADING_PX = {1: 18, 2: 16, 3: 15, 4: 14, 5: 14, 6: 14}


def _preprocess(md: str) -> str:
    """Fix up model markdown before parsing."""
    # The backend injects tool status as a blockquote ("> Running foo…"),
    # which Qt renders indented — strip the quote marker on those lines only.
    md = re.sub(r"(?m)^\s*>\s*(?=Running\b)", "", md)

    # python-markdown + nl2br needs a blank line before a list or the items
    # fold into the previous paragraph as <br> lines. Insert one when a list
    # starts right after a non-list, non-blank line.
    out: list[str] = []
    for ln in md.split("\n"):
        if _LIST_RE.match(ln) and out:
            prev = out[-1]
            if prev.strip() and not _LIST_RE.match(prev):
                out.append("")
        out.append(ln)
    return "\n".join(out)


def _demote_headings(html: str) -> str:
    """Rewrite <h1..6> as sized, bold <div>s (Qt ignores heading font-size)."""
    def repl(m: re.Match) -> str:
        level = int(m.group(1))
        inner = m.group(2)
        px = _HEADING_PX.get(level, 14)
        top = 12 if level <= 2 else 8
        return (
            f'<div style="font-size:{px}px; font-weight:700; '
            f'margin-top:{top}px; margin-bottom:2px;">{inner}</div>')

    return re.sub(r"<h([1-6])>(.*?)</h\1>", repl, html, flags=re.S)


def markdown_to_html(md: str, *, allow_html: bool = True) -> str:
    """Convert assistant markdown to Qt-friendly, styled HTML.

    ``allow_html=False`` escapes raw HTML in the input instead of passing it
    through: for text that is not ours (SIEM alerts quote the monitored
    system's file names and log lines)."""
    conv = markdown.Markdown(extensions=list(_MD_EXTENSIONS))
    if not allow_html:
        conv.preprocessors.deregister("html_block")
        conv.inlinePatterns.deregister("html")
    html = conv.convert(_preprocess(md))
    return _demote_headings(html)


def stylesheet(fg: str) -> str:
    """Default stylesheet for the rich-text document, resolved per theme."""
    is_dark = theme.is_dark()
    code_bg = "#1E242C" if is_dark else "#F1F3F5"
    code_fg = "#E6EDF3" if is_dark else "#24292F"
    border = theme.color("border")
    link = "#4EA3FF" if is_dark else theme.color("accent")
    mono = "'SF Mono','Menlo','Consolas','Courier New',monospace"
    return (
        f"a {{ color: {link}; }}"
        f"code {{ font-family: {mono}; font-size: 13px; "
        f"background-color: {code_bg}; color: {code_fg}; }}"
        f"pre {{ font-family: {mono}; font-size: 13px; "
        f"background-color: {code_bg}; color: {code_fg}; }}"
        f"th {{ border: 1px solid {border}; padding: 4px 10px; "
        f"background-color: {code_bg}; }}"
        f"td {{ border: 1px solid {border}; padding: 4px 10px; }}"
        f"p {{ color: {fg}; }}"
    )
