"""Shared markdown utilities for the chat plugin."""
from __future__ import annotations

import re

_BOX_CHARS = frozenset("\u250c\u2510\u2514\u2518\u251c\u2524\u252c\u2534\u253c\u2500\u2502\u256d\u256e\u256f\u2570\u2571\u2572\u25b2\u25bc\u25c4\u25ba\u2550\u2551\u2554\u2557\u255a\u255d\u2560\u2563\u2566\u2569\u256c")


def is_box_drawing(line: str) -> bool:
    """Return True if *line* looks like an ASCII art / box diagram."""
    return bool(line and _BOX_CHARS.intersection(line))


def strip_inline_md(text: str) -> str:
    """Strip inline markdown markers, returning plain text."""
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'~~(.+?)~~', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'`(.+?)`', r'\1', text)
    text = re.sub(r'\[(.+?)\]\([^)]+\)', r'\1', text)
    return text


_HEADING_RE = re.compile(r'^\s*#{1,6}\s+')
_BLOCKQUOTE_RE = re.compile(r'^\s*>\s?')
_HRULE_RE = re.compile(r'^\s*(?:---|\*\*\*|___)\s*$')
_LIST_BULLET_RE = re.compile(r'^(\s*)([*+-])\s+')
# Markdown table header-separator: `|---|---|` or `|:--:|:--|` (alignment
# markers allowed). Used to identify and drop the divider line that
# would otherwise read as ASCII noise in a streaming prose view.
_TABLE_SEP_CHARS = set("|-: \t")


def _is_table_row(line: str) -> bool:
    """A line that looks like a markdown table row: starts and ends with
    ``|`` and has at least two cell separators."""
    stripped = line.strip()
    return (stripped.startswith('|')
            and stripped.endswith('|')
            and stripped.count('|') >= 2)


def _is_table_separator(line: str) -> bool:
    """A line that contains only the separator characters used in a
    markdown table header divider (``|``, ``-``, ``:``, whitespace)."""
    stripped = line.strip()
    return (bool(stripped)
            and not (set(stripped) - _TABLE_SEP_CHARS)
            and '-' in stripped)


def _strip_table_row(line: str) -> str:
    """Convert ``| cell | cell |`` to ``cell  cell`` so the row reads as
    plain text without the pipe noise."""
    stripped = line.strip()
    if stripped.startswith('|'):
        stripped = stripped[1:]
    if stripped.endswith('|'):
        stripped = stripped[:-1]
    cells = [c.strip() for c in stripped.split('|')]
    return '  '.join(cells)


def strip_streaming_md(text: str) -> str:
    """Render markdown as clean prose for the streaming placeholder.

    The streaming bubble used to display the raw markdown text — users
    saw ``**bold**`` literally until MarkdownRenderer ran at finalize,
    then the same text re-rendered as actual bold. That two-pass jump
    looks like the model is "fixing" its own output and is jarring.

    During streaming we can't easily run the full markdown renderer
    (it builds CTkTextbox + embedded widgets and re-renders on every
    chunk would be expensive). Instead, strip the syntax markers so
    the user sees clean prose, then MarkdownRenderer takes over at
    finalize with proper bold/italic/headings/tables/code — a graceful
    upgrade rather than a "raw → formatted" flip.

    Strips: bold / italic / strikethrough / inline-code / links via
    strip_inline_md, plus heading hashes, blockquote prefixes, code
    fence delimiters, and horizontal-rule lines. List bullets are
    kept (they already read naturally as text), and partial inline
    tokens (e.g. ``**hello`` with no closing ``**`` yet) stay as-is
    until they complete on a later chunk.
    """
    # Block-level pass FIRST — strip_inline_md's `(.+?)` regex would
    # otherwise treat the outer two backticks of a ``` fence as inline
    # code and collapse them, leaving a stray backtick that no longer
    # matches the fence pattern. Process lines first, then apply the
    # inline strip to non-fenced content.
    out_lines: list[str] = []
    in_code_block = False
    for line in text.splitlines():
        stripped = line.strip()
        # Code fences: drop the fence line entirely; let the content
        # inside flow as plain text (it's already source-shaped).
        if stripped.startswith('```') or stripped.startswith('~~~'):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            # Code is already plain; don't run inline strip on it
            # (would mangle in-code asterisks, backticks, etc.).
            out_lines.append(line)
            continue
        # Horizontal rules → blank line so the visual break is preserved.
        if _HRULE_RE.match(line):
            out_lines.append("")
            continue
        # Markdown table: the divider line (`|---|---|`) is pure noise
        # in a prose view — drop it. Data + header rows get their
        # outer pipes stripped and the inner ones collapsed to two
        # spaces, so the row reads as space-aligned columns rather
        # than `| 011 | francis_ubuntu | 10.49.64.5 |`. MarkdownRenderer
        # rebuilds the proper table at finalize.
        if _is_table_separator(line):
            continue
        if _is_table_row(line):
            out_lines.append(strip_inline_md(_strip_table_row(line)))
            continue
        # Heading hashes → the heading text alone. Loses the size cue
        # (we can't restyle within a single-font CTkLabel) but removes
        # the literal "###".
        m = _HEADING_RE.match(line)
        if m:
            out_lines.append(strip_inline_md(line[m.end():]))
            continue
        # Blockquote markers → quoted text without the ">" prefix.
        m = _BLOCKQUOTE_RE.match(line)
        if m:
            out_lines.append(strip_inline_md(line[m.end():]))
            continue
        out_lines.append(strip_inline_md(line))
    return "\n".join(out_lines)
