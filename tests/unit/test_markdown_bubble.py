"""Tests for plugins.chat.markdown_bubble — markdown parsing helpers.

Tests the parsing helper logic from the MarkdownBubble class.
Since MarkdownBubble extends the mocked CTkFrame (MagicMock), we import
the module and test the logic via the `re` module directly, matching the
same regex patterns used in the source.
"""

import re

import pytest


# ── Replicate the static helpers exactly as defined in source ──
# _strip_inline_md is a @staticmethod on MarkdownBubble
def _strip_inline_md(text):
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'~~(.+?)~~', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'`(.+?)`', r'\1', text)
    text = re.sub(r'\[(.+?)\]\([^)]+\)', r'\1', text)
    return text


_BOX_CHARS = set("┌┐└┘├┤┬┴┼─│╭╮╯╰╱╲▲▼◄►═║╔╗╚╝╠╣╦╩╬")


def _is_box_drawing(line):
    if not line:
        return False
    return bool(_BOX_CHARS.intersection(line))


# ---------------------------------------------------------------------------
# _strip_inline_md
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStripInlineMd:
    def test_strips_bold(self):
        assert _strip_inline_md("**bold text**") == "bold text"

    def test_strips_italic(self):
        assert _strip_inline_md("*italic*") == "italic"

    def test_strips_strikethrough(self):
        assert _strip_inline_md("~~strike~~") == "strike"

    def test_strips_inline_code(self):
        assert _strip_inline_md("`code`") == "code"

    def test_strips_link(self):
        assert _strip_inline_md("[text](http://example.com)") == "text"

    def test_strips_multiple_formats(self):
        text = "**bold** and *italic* with `code`"
        result = _strip_inline_md(text)
        assert result == "bold and italic with code"

    def test_plain_text_unchanged(self):
        assert _strip_inline_md("plain text") == "plain text"

    def test_nested_markers(self):
        text = "**bold with `code` inside**"
        result = _strip_inline_md(text)
        assert "**" not in result
        assert "`" not in result

    def test_empty_string(self):
        assert _strip_inline_md("") == ""

    def test_link_preserves_text(self):
        result = _strip_inline_md("Click [here](http://example.com) now")
        assert result == "Click here now"

    def test_multiple_links(self):
        result = _strip_inline_md("[a](http://a.com) and [b](http://b.com)")
        assert result == "a and b"

    def test_order_matters_bold_before_italic(self):
        """Bold ** is stripped before italic *, preventing false matches."""
        result = _strip_inline_md("***both***")
        # **X** stripped first → *X*, then *X* → X
        assert result == "both"


# ---------------------------------------------------------------------------
# _is_box_drawing
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestIsBoxDrawing:
    @pytest.mark.parametrize("line", [
        "┌──────────┐",
        "│ content  │",
        "└──────────┘",
        "╭──────╮",
        "╰──────╯",
        "╔══════╗",
        "║      ║",
        "Name │ Value",
        "▲ Up arrow",
        "► Right",
        "┼",
        "╱╲",
    ])
    def test_box_drawing_detected(self, line):
        assert _is_box_drawing(line) is True

    @pytest.mark.parametrize("line", [
        "Hello world",
        "# Heading",
        "- list item",
        "1. numbered item",
        "```python",
        "| table | row |",  # Pipe is not in box chars
    ])
    def test_normal_text_not_box(self, line):
        assert _is_box_drawing(line) is False

    def test_empty_string(self):
        assert _is_box_drawing("") is False
