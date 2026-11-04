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

import html
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


_FENCE_RE = re.compile(r"^(\s*)(```|~~~)")


def _normalize_lists(md: str) -> str:
    """Re-indent lists and the code fences inside them for python-markdown.

    Models indent sub-items by 2 or 3 spaces; python-markdown wants 4 per
    level, or the items fold into the parent's paragraph as "- foo" lines.
    And it only knows fences at the left margin: one inside a list item
    became inline code, its lines run together. So list lines are put on a
    4-space grid, and a fence in a list becomes an indented code block
    (8 spaces past its item's text), which python-markdown does nest.
    """
    out: list[str] = []
    stack: list[int] = []      # source indents of the open list levels
    fence = None               # (marker, source indent, output indent) in a list fence
    top_fence = None           # marker of a fence at the left margin
    for ln in md.split("\n"):
        if top_fence:
            out.append(ln)
            if ln.strip().startswith(top_fence):
                top_fence = None
            continue
        if fence:
            marker, src, dst = fence
            if ln.strip().startswith(marker) and not ln.strip().strip(marker[0]):
                fence = None
                out.append("")
            else:
                body = ln[src:] if ln[:src].strip() == "" else ln.lstrip()
                out.append(" " * dst + body if body.strip() else "")
            continue
        if not ln.strip():
            out.append(ln)
            continue
        indent = len(ln) - len(ln.lstrip())
        m = _FENCE_RE.match(ln)
        if m:
            if stack and indent > 0:
                depth = sum(1 for i in stack if i < indent)
                fence = (m.group(2), indent, 4 * depth + 4)
                out.append("")
                continue
            stack.clear()
            top_fence = m.group(2)
            out.append(ln)
            continue
        if _LIST_RE.match(ln):
            # python-markdown + nl2br needs a blank line before a list or the
            # items fold into the previous paragraph as <br> lines.
            if out and out[-1].strip() and not _LIST_RE.match(out[-1]):
                out.append("")
            while stack and stack[-1] > indent:
                stack.pop()
            if not stack or stack[-1] < indent:
                stack.append(indent)
            out.append(" " * (4 * (len(stack) - 1)) + ln.lstrip())
            continue
        if indent and stack:
            # Continuation text of the innermost item that starts left of it.
            depth = sum(1 for i in stack if i < indent)
            out.append(" " * (4 * depth) + ln.lstrip())
            continue
        stack.clear()
        out.append(ln)
    return "\n".join(out)


# The backend streams tool progress into the reply: "> Running **tool**...\n"
# before each tool call, and a "⏳" every few seconds while a slow one runs.
_STATUS_RE = re.compile(r"^\s*(?:>\s*)?Running \*\*([^*\n]+)\*\*\.{3}\s*$")
# Hourglasses with text after them: the wait is over. A trailing one stays as
# the live "still working" sign (the greedy run backtracks to leave one).
_HOURGLASS_RE = re.compile(r"⏳+(?=\s*\S)")


def _status_lines(md: str, allow_html: bool) -> str:
    """Tool status lines as their own muted paragraph, apart from the reply.

    Left as they come, the status line and the hourglasses ran into the
    reply's first line. A tool is "Running" while nothing follows it, "Ran"
    once the reply does."""
    md = _HOURGLASS_RE.sub("", md)
    lines = md.split("\n")
    waiting = False
    if lines and lines[-1].strip() == "⏳" and len(lines) > 1:
        lines.pop()  # shown on the status line it belongs to
        waiting = True
    out: list[str] = []
    for i, ln in enumerate(lines):
        m = _STATUS_RE.match(ln)
        if not m:
            out.append(ln)
            continue
        done = any(t.strip() for t in lines[i + 1:])
        text = f"{'Ran' if done else 'Running'} {m.group(1).strip()}{'' if done else '…'}"
        if waiting and not done:
            text += " ⏳"
        if allow_html:
            text = (f'<span style="color:{theme.color("text_secondary")}; font-size:12px;">'
                    f"{html.escape(text)}</span>")
        else:
            text = f"*{text}*"
        if out and out[-1].strip() and not _STATUS_RE.match(lines[i - 1]):
            out.append("")
        out.append(text)
        nxt = next((t for t in lines[i + 1:] if t.strip()), None)
        if nxt is not None and not _STATUS_RE.match(nxt):
            out.append("")
    return "\n".join(out)


def _preprocess(md: str, allow_html: bool = True) -> str:
    """Fix up model markdown before parsing."""
    return _normalize_lists(_status_lines(md, allow_html))


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
    out = conv.convert(_preprocess(md, allow_html))
    return _demote_headings(out)


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
