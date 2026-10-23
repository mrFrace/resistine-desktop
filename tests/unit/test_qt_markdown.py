"""
Unit tests for plugins/chat/qt_markdown.py: model markdown that python-markdown
gets wrong on its own.

- sub-items indented 2 or 3 spaces nest instead of folding into "- foo" lines
- a code fence inside a list item stays a code block, one command per line
- fences at the left margin, and the list-looking lines in them, are left alone
"""
import pytest

pytest.importorskip("markdown")

from plugins.chat.qt_markdown import _normalize_lists, markdown_to_html  # noqa: E402

REPLY = """**Remediation Priorities:**

1. **Priority 1**:
   - **Issue**: World-writable files
   - **Commands**:
     ```
     chmod 644 /a/one.svg
     chmod 644 /a/two.svg
     ```

2. **Priority 2**:
   - **Issue**: x
"""


@pytest.mark.unit
class TestLists:
    @pytest.mark.parametrize("sub", ["  ", "   ", "    "])
    def test_sub_items_nest(self, sub):
        html = markdown_to_html(f"1. **Score**:\n{sub}- one\n{sub}- two\n2. next\n")
        assert html.count("<ul>") == 1 and html.count("<li>") == 4
        assert "- one" not in html

    def test_fence_in_a_list_is_a_code_block(self):
        html = markdown_to_html(REPLY)
        assert "<pre><code>chmod 644 /a/one.svg\nchmod 644 /a/two.svg\n</code></pre>" in html
        assert "```" not in html
        # Priority 2 still belongs to the same ordered list.
        assert html.count("<ol>") == 1

    def test_continuation_text_stays_in_its_item(self):
        html = markdown_to_html("1. first\n   more about first\n2. second\n")
        assert html.count("<li>") == 2 and "more about first" in html

    def test_left_margin_fence_untouched(self):
        md = "Run:\n\n```\n- not a list\n   indented\n```\n"
        assert _normalize_lists(md) == md
        html = markdown_to_html(md)
        assert "<pre><code>- not a list\n   indented\n</code></pre>" in html

    def test_list_lines_inside_a_list_fence_are_code(self):
        md = "- steps:\n  ```\n  - keep me\n  ```\n"
        assert "<pre><code>- keep me\n</code></pre>" in markdown_to_html(md)

    def test_plain_text_unchanged(self):
        md = "Hello\nworld\n\n**Summary:** done."
        assert _normalize_lists(md) == md
