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


# Tool progress the backend streams into the reply.
@pytest.mark.unit
def test_status_line_is_its_own_paragraph_and_hourglasses_go():
    md = "> Running **calculate_risk_score**...\n⏳⏳⏳Risk score for AnubisAI: **63**"
    out = markdown_to_html(md)
    assert "⏳" not in out
    assert "Ran calculate_risk_score</span></p>" in out
    assert "<p>Risk score for AnubisAI: <strong>63</strong></p>" in out


@pytest.mark.unit
def test_running_tool_keeps_one_hourglass():
    out = markdown_to_html("> Running **get_security_status**...\n⏳⏳")
    assert "Running get_security_status… ⏳</span>" in out
    assert out.count("⏳") == 1


@pytest.mark.unit
def test_hourglass_before_any_tool_stays():
    assert "⏳" in markdown_to_html("⏳⏳⏳")


@pytest.mark.unit
def test_consecutive_tools_and_heading_after():
    md = "> Running **a_tool**...\n> Running **b_tool**...\n## Security posture\nok"
    out = markdown_to_html(md)
    assert "Ran a_tool" in out and "Ran b_tool" in out
    assert "Ran a_tool</span><br />" in out  # one muted block, one tool per line
    assert "b_tool</span></p>\n<div" in out and "Security posture</div>" in out


@pytest.mark.unit
def test_status_without_html_is_plain_italics():
    out = markdown_to_html("> Running **x_y**...\nDone", allow_html=False)
    assert "<em>Ran x_y</em>" in out and "<p>Done</p>" in out
