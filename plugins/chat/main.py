"""Phoenix AI Chat plugin (PyQt6).

Faithful PyQt6 port of the original CustomTkinter chat screen. Reproduces the
same regions 1:1:

  * Top bar  -- hamburger menu toggle (left), "Phoenix AI" title (centre),
                "+" New Chat button (right).
  * History drawer -- a collapsible left panel listing saved sessions with
                select + delete, slid open/closed by the hamburger, dimming the
                chat behind it.
  * Message area -- a vertically scrolling list of user bubbles (right-aligned,
                blue) and assistant bubbles (left-aligned, rendered as MARKDOWN
                via Qt's MarkdownText format).
  * Welcome screen -- centred greeting + "TRY ASKING" suggestion chips when the
                conversation is empty (or an "API key required" panel when no
                client is configured).
  * Input bar -- rounded entry "Message Phoenix AI..." + a send button that
                shows "↑" and toggles to a red "■" stop glyph while streaming.

The streaming controller, history manager and markdown utilities are reused
verbatim from the framework-agnostic backend modules.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""
from __future__ import annotations

import os

from PyQt6.QtCore import (
    QEasingCurve,
    QObject,
    QPropertyAnimation,
    QSize,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QApplication,
    QStyle,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from plugins.base_plugin import BasePlugin
from plugins.chat import siem_alerts
from plugins.chat.history import ChatHistoryManager
from plugins.chat.qt_markdown import markdown_to_html, stylesheet
from plugins.chat.streaming import StreamController
from plugins.chat.suggestions import pick_suggestions
from utils import chat_config, settings
from utils.logger import logger

# Appended to history when the user navigates away mid-response: the partial
# text is discarded and this canned marker is stored instead.
_NAV_AWAY_MSG = (
    "_(You switched chats before this response could finish. "
    "Please ask your question again.)_"
)

_SYSTEM_PROMPT = "You are SOC Copilot specialized in cybersecurity."
_ICON_DIR = os.path.dirname(os.path.realpath(__file__))
_SYS_MSG = {"role": "system", "content": _SYSTEM_PROMPT}
_DEFAULT_BASE_URL = chat_config.DEFAULT_BASE_URL

# Thinking spinner (braille) shown while waiting for the first token, ported
# in spirit from the CustomTkinter build's AssistantBubble. Suppressed when
# the user ticks "Disable typing animation" in Settings. Deliberately NO
# in-text blinking cursor during streaming: appending/removing a glyph to a
# word-wrapped Markdown label re-wraps the whole document every blink, which
# made the bubble visibly jitter.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_MS = 80

# Message-arrival animation: fade + 12px slide, OutQuad, one beat.
_ARRIVE_MS = 200


def _tls_verify() -> str | bool:
    """httpx ``verify`` value for the HTTPS chat endpoint.

    The dashboard's certificate is signed either by the internal Resistine
    root CA (leaf-only, no intermediate) or by the Cloudflare Origin CA
    (*.phoenix.exposed). Neither is in certifi, so the app ships both roots
    in ``resources/certs/chat-ca-bundle.pem``. Resolution order:
    RESISTINE_CA_BUNDLE env var, a ``certs/resistine-rootCA.pem`` override in
    the config dir, then the bundled CA file. If all are missing (shouldn't
    happen -- the bundle ships in resources/), fall back to standard
    verification rather than disabling it.
    """
    ca = os.environ.get("RESISTINE_CA_BUNDLE")
    if ca and os.path.isfile(ca):
        return ca
    ca = os.path.join(
        settings.get_config_dir(), "certs", "resistine-rootCA.pem")
    if os.path.isfile(ca):
        return ca
    from utils.functions import get_resource_path
    for name in ("chat-ca-bundle.pem", "resistine-rootCA.pem"):
        ca = get_resource_path(os.path.join("resources", "certs", name))
        if os.path.isfile(ca):
            return ca
    return True

BRAND_BLUE = "#1E6FD9"
_ACCENT_HOVER = "#185CB5"
_STOP_RED = "#EF4444"
_STOP_RED_HOVER = "#DC2626"

# Bubble width caps (mirror plugins/chat/bubble.py).
# Width ceilings for bubbles. The effective width is dynamic — a fraction of
# the visible chat area, clamped to these caps (see _apply_bubble_widths) —
# so bubbles use the room they're given instead of wrapping at a fixed 480px.
_ASST_MAX = 860
_USER_MAX = 720
_BUBBLE_FRACTION = 0.78  # of the message-area viewport width

_SIDEBAR_WIDTH = 240


# ---------------------------------------------------------------------------
# Bubble widgets
# ---------------------------------------------------------------------------

class _Bubble(QFrame):
    """A single chat bubble.

    User messages are a filled blue pill (QLabel, plain text). Assistant
    messages are panel-less rich text rendered from markdown via a styled,
    auto-sized QTextBrowser (Claude-style — reads as the app talking, not a
    card floating over the page).
    """

    def __init__(self, *, is_user: bool, max_width: int):
        super().__init__()
        self._is_user = is_user
        self._max_width = max_width
        self._raw_text = ""
        self._has_content = False  # gates copy/hover until real text lands

        # Thinking-spinner state (assistant only).
        self._spinner_idx = 0
        self._spinner_timer: QTimer | None = None
        self._thinking = False

        self.setSizePolicy(QSizePolicy.Policy.Maximum,
                           QSizePolicy.Policy.Preferred)
        self.setObjectName("ChatBubble")

        lay = QVBoxLayout(self)
        lay.setSpacing(0)

        if is_user:
            self._build_user(lay, max_width)
        else:
            self._build_assistant(lay, max_width)

    # -- construction ------------------------------------------------------

    def _build_user(self, lay: QVBoxLayout, max_width: int) -> None:
        bg = theme.color("bubble_user_bg")
        self._fg = theme.color("bubble_user_text")
        self.setStyleSheet(
            f"#ChatBubble {{ background-color: {bg}; "
            f"border: 1px solid {bg}; border-radius: 16px; }}"
            f"#ChatBubble:hover {{ background-color: {_ACCENT_HOVER}; "
            f"border-color: {_ACCENT_HOVER}; }}")
        lay.setContentsMargins(14, 10, 14, 10)

        self._label = QLabel()
        self._view = None
        self._label.setObjectName("ChatBubbleText")
        self._label.setWordWrap(True)
        # Highlight-by-mouse only — no keyboard flag, so a click doesn't
        # plant a blinking caret and read as an editable field.
        self._label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self._label.setCursor(QCursor(Qt.CursorShape.IBeamCursor))
        self._label.setStyleSheet(
            f"#ChatBubbleText {{ background: transparent; border: none; "
            f"color: {self._fg}; font-size: 14px; }}")
        self._label.setTextFormat(Qt.TextFormat.PlainText)
        self._label.setMaximumWidth(max_width)
        lay.addWidget(self._label)

        # No copy button on user bubbles.
        self._copy_btn = None
        self._copy_eff = None
        self._copy_anim = None
        self._copy_row = None

    def _build_assistant(self, lay: QVBoxLayout, max_width: int) -> None:
        self._fg = theme.color("bubble_ai_text")
        # Panel-less: transparent frame, text sits on the page.
        self.setStyleSheet("#ChatBubble { background: transparent; }")
        lay.setContentsMargins(12, 2, 12, 2)

        self._label = None
        self._view = QTextBrowser()
        self._view.setObjectName("ChatBubbleText")
        self._view.setFrameShape(QFrame.Shape.NoFrame)
        self._view.setOpenExternalLinks(True)  # markdown links → browser
        self._view.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # Read-only browser shows no caret; mouse-select + link-click only.
        self._view.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.LinksAccessibleByMouse)
        self._view.document().setDocumentMargin(3)
        self._view.document().setDefaultStyleSheet(stylesheet(self._fg))
        self._view.setStyleSheet(
            "QTextBrowser#ChatBubbleText { background: transparent; "
            f"border: none; color: {self._fg}; font-size: 14px; }}")
        # Fixed full-column width from the start: only height grows as text
        # streams in, so there is zero horizontal jitter (the old width-lock,
        # now inherent to the sized browser).
        self._view.setFixedWidth(max_width)
        lay.addWidget(self._view)

        self._start_thinking()

        # Copy button below the response — space reserved from the start so
        # the bubble height never jumps; opacity fades it in on hover.
        self._copy_btn = self._build_copy_button()
        self._copy_eff = QGraphicsOpacityEffect(self._copy_btn)
        self._copy_eff.setOpacity(0.0)
        self._copy_btn.setGraphicsEffect(self._copy_eff)
        self._copy_anim = None
        self._copy_row = QHBoxLayout()
        self._copy_row.setContentsMargins(0, 2, 0, 0)
        self._copy_row.setSpacing(4)
        self._copy_row.addWidget(self._copy_btn)
        self._copy_row.addStretch(1)
        lay.addLayout(self._copy_row)

    def _build_copy_button(self) -> QPushButton:
        muted = theme.color("text_secondary")
        btn = QPushButton("⧉  Copy")
        btn.setObjectName("ChatCopyBtn")
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setFlat(True)
        btn.setStyleSheet(
            "#ChatCopyBtn { background: transparent; border: none; "
            f"color: {muted}; font-size: 12px; padding: 2px 4px; }}"
            "#ChatCopyBtn:hover { text-decoration: underline; }")
        # Stays visible (space reserved) from construction — hiding it and
        # revealing at first content made the bubble height jump mid-stream.
        # It's invisible anyway until hover fades its opacity up.
        btn.clicked.connect(self._copy_to_clipboard)
        return btn

    def _copy_to_clipboard(self) -> None:
        if not self._has_content:
            return  # nothing to copy while thinking
        QApplication.clipboard().setText(self._raw_text)
        if self._copy_btn is None:
            return
        self._copy_btn.setText("✓  Copied")
        QTimer.singleShot(1500, self._reset_copy_label)

    def _reset_copy_label(self) -> None:
        # Fires 1.5s later — the bubble may have been torn down by then, in
        # which case _copy_btn is a live Python wrapper around a deleted C++
        # object (truthy, but setText raises). Guard both.
        try:
            if self._copy_btn is not None:
                self._copy_btn.setText("⧉  Copy")
        except RuntimeError:
            pass

    # -- hover: fade the copy button in/out --------------------------------

    def enterEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().enterEvent(event)
        self._fade_copy(1.0)

    def leaveEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().leaveEvent(event)
        self._fade_copy(0.0)

    def _fade_copy(self, target: float) -> None:
        if (self._copy_eff is None or self._copy_btn is None
                or not self._has_content):
            return
        anim = QPropertyAnimation(self._copy_eff, b"opacity", self)
        anim.setDuration(120)
        anim.setEndValue(target)
        anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._copy_anim = anim  # keep a ref so it isn't GC'd mid-flight

    def add_retry(self, callback) -> None:
        """Swap the copy affordance for a Retry button (error bubbles)."""
        if self._copy_row is None:
            return
        muted = theme.color("text_secondary")
        btn = QPushButton("↻  Retry")
        btn.setObjectName("ChatRetryBtn")
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setFlat(True)
        btn.setStyleSheet(
            f"#ChatRetryBtn {{ background: transparent; border: none; "
            f"color: {muted}; font-size: 12px; padding: 2px 4px; }}"
            f"#ChatRetryBtn:hover {{ text-decoration: underline; }}")
        btn.clicked.connect(callback)
        if self._copy_btn is not None:
            self._copy_btn.setVisible(False)
        self._copy_row.insertWidget(0, btn)

    # -- thinking spinner --------------------------------------------------

    def _start_thinking(self) -> None:
        """Show the animated braille thinking spinner (assistant only).

        Always animated — the Settings 'Disable typing animation' toggle
        governs how the response TEXT renders (stream-in vs all-at-once),
        not this loading indicator.
        """
        self._thinking = True
        self._render_thinking()
        self._spinner_timer = QTimer(self)
        self._spinner_timer.timeout.connect(self._tick_spinner)
        self._spinner_timer.start(_SPINNER_MS)

    def _render_thinking(self) -> None:
        frame = _SPINNER_FRAMES[self._spinner_idx % len(_SPINNER_FRAMES)]
        muted = theme.color("text_secondary")
        try:
            self._view.setHtml(
                f'<span style="color:{muted}; font-style:italic;">'
                f"Thinking &nbsp; {frame}</span>")
        except RuntimeError:
            # View deleted while the spinner timer was still pending — stop
            # ticking so it can't fire against the dead object again.
            self._end_thinking()
            return
        self._fit_height()

    def _tick_spinner(self) -> None:
        self._spinner_idx += 1
        self._render_thinking()

    def _end_thinking(self) -> None:
        self._thinking = False
        if self._spinner_timer is not None:
            self._spinner_timer.stop()
            self._spinner_timer = None

    def _fit_height(self) -> None:
        """Size the browser to its content (no internal scrolling).

        Lay the document out at the STABLE ``_max_width`` — reading
        ``self._view.width()`` mid-stream can return a transient value
        before the layout settles, which makes the document wrap
        differently than it renders and clips the last line. A one-line
        floor + bottom padding covers block margins and descenders.
        """
        try:
            doc = self._view.document()
            doc.setTextWidth(self._max_width)
            line = self._view.fontMetrics().lineSpacing()
            h = max(doc.size().height(), line)
            self._view.setFixedHeight(int(h) + 8)
        except RuntimeError:
            # The browser's C++ object was deleted (chat cleared/rebuilt or
            # session switched) while a deferred relayout was still pending.
            pass

    def set_text(self, text: str, *, streaming: bool = False) -> None:
        del streaming  # accepted for call-site clarity; no behavioural effect
        if self._is_user:
            self._raw_text = text
            try:
                self._label.setText(text)
                self._fit_user_width()
            except RuntimeError:
                pass
            return
        # Assistant: strip the leading whitespace the backend sometimes emits
        # (renders as a first-line indent), then render styled HTML.
        text = text.lstrip()
        self._raw_text = text
        if self._thinking and text:
            self._end_thinking()
        try:
            self._view.setHtml(markdown_to_html(text) if text else "")
        except RuntimeError:
            # Browser deleted mid-stream (session switched / chat torn down).
            return
        self._fit_height()
        if text and text != "…":
            self._has_content = True  # enables copy + hover reveal

    def _fit_user_width(self) -> None:
        """Size the user pill to its text, up to ``_max_width``.

        A word-wrapped QLabel's size hint is a narrow heuristic width, not
        the room available, so short and medium messages wrapped into a
        thin column. Pin the width to the longest line (plus a little
        slack for rounding), capped by the bubble's max width; longer text
        then wraps at the full width.
        """
        self._label.ensurePolished()  # stylesheet font (14px) before measuring
        fm = self._label.fontMetrics()
        lines = self._raw_text.splitlines() or [""]
        natural = max(fm.horizontalAdvance(line) for line in lines) + 4
        self._label.setFixedWidth(max(1, min(natural, self._max_width)))

    def set_max_width(self, max_width: int) -> None:
        self._max_width = max_width
        try:
            if self._is_user:
                self._label.setMaximumWidth(max_width)
                self._fit_user_width()
            else:
                self._view.setFixedWidth(max_width)
                self._fit_height()
        except RuntimeError:
            # Bubble's underlying C++ widget was deleted while a resize/
            # relayout (e.g. _apply_bubble_widths on a chat-area resize) was
            # still iterating stale rows. Nothing to size — ignore.
            pass


class _BubbleRow(QWidget):
    """Full-width row holding one bubble, aligned left or right."""

    def __init__(self, bubble: _Bubble, *, is_user: bool):
        super().__init__()
        self._is_user = is_user
        self._anims: tuple | None = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 4, 12, 4)
        lay.setSpacing(0)
        if is_user:
            lay.addStretch(1)
            lay.addWidget(bubble)
        else:
            lay.addWidget(bubble)
            lay.addStretch(1)
        self.bubble = bubble

    def play_arrival(self) -> None:
        """Fade the bubble into place (~200ms, OutQuad).

        Fade ONLY — an earlier version also slid the bubble by animating
        the row's layout margins, but that forces a full layout pass of
        the message column every frame (60fps × two rows + the scroll
        animation), which showed up as vertical twitching. Opacity is a
        pure paint effect: zero relayout. The effect is removed on finish
        so streaming renders on the normal fast path afterwards.
        """
        eff = QGraphicsOpacityEffect(self.bubble)
        self.bubble.setGraphicsEffect(eff)
        eff.setOpacity(0.0)
        fade = QPropertyAnimation(eff, b"opacity", self)
        fade.setDuration(_ARRIVE_MS)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutQuad)
        fade.finished.connect(
            lambda: self.bubble.setGraphicsEffect(None))
        fade.start()
        self._anims = (fade,)  # keep ref — GC'd anims never finish


class _ChatInput(QTextEdit):
    """Multi-line auto-expanding chat input.

    - Grows with content up to ``_MAX_LINES`` lines, then scrolls internally.
    - Enter sends (``send_requested``); Shift+Enter inserts a newline.
    - Tab moves focus (send button next) instead of inserting \\t.
    - ``focus_changed`` lets the owner draw a focus ring on the input bar.

    Exposes ``text()``/``setText()`` so existing QLineEdit call sites keep
    working unchanged.
    """

    send_requested = pyqtSignal()
    focus_changed = pyqtSignal(bool)

    _MAX_LINES = 5

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptRichText(False)
        self.setTabChangesFocus(True)
        self.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)
        self.document().setDocumentMargin(2)
        self.textChanged.connect(self._fit_height)
        self._fit_height()

    # QLineEdit-compatible accessors -----------------------------------
    def text(self) -> str:
        return self.toPlainText()

    def setText(self, text: str) -> None:  # noqa: N802 (Qt-style name)
        self.setPlainText(text)
        # Jump the cursor to the end, like QLineEdit.setText felt.
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.setTextCursor(cursor)

    # Key handling ------------------------------------------------------
    def keyPressEvent(self, event) -> None:  # noqa: N802 (Qt override)
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (
                event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
            self.send_requested.emit()
            return
        super().keyPressEvent(event)

    def focusInEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().focusInEvent(event)
        self.focus_changed.emit(True)

    def focusOutEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().focusOutEvent(event)
        self.focus_changed.emit(False)

    # Auto-expand -------------------------------------------------------
    def _fit_height(self) -> None:
        line = self.fontMetrics().lineSpacing()
        pad = 16  # stylesheet padding + document margin allowance
        min_h = int(line + pad)
        max_h = int(line * self._MAX_LINES + pad)
        doc_h = self.document().size().height()
        if doc_h <= 0:
            # Document layout not ready yet (widget not shown) — fall back
            # to hard newline count; soft wraps are re-fit on resize/show.
            doc_h = self.document().blockCount() * line + 4
        self.setFixedHeight(max(min_h, min(int(doc_h) + pad - 4, max_h)))

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt override)
        # Width changes alter soft-wrapping, which changes needed height.
        super().resizeEvent(event)
        self._fit_height()


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class _AlertBridge(QObject):
    """Carries a SIEM alert from the Matrix thread to the Qt thread (the
    signal is emitted there and delivered queued to the GUI-thread slot)."""

    arrived = pyqtSignal(dict)


def _alert_markdown(alert: dict) -> str:
    import time as _time
    when = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(alert.get("ts") or 0))
    return f"**🚨 SIEM alert** · {when}\n\n{alert.get('body', '')}"


class Plugin(BasePlugin):
    """Chat plugin -- lets users talk to an OpenAI-compatible AI assistant."""

    defer_reveal_until_settled = True

    def __init__(self, app):
        super().__init__(
            id="002", version="2025.01.01", order=2, name="Chat", status=None,
            description="Ask the Phoenix AI security assistant.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Chat", "ES": "Chat", "FR": "Chat"},
            icon_light_path=os.path.join(_ICON_DIR, "chat_light.png"),
            icon_dark_path=os.path.join(_ICON_DIR, "chat_dark.png"))
        self.app = app
        self.client = None
        self.conversation_history: list[dict] = []
        self._stream_ctrl: StreamController | None = None
        self._history = ChatHistoryManager()
        # One-shot cleanup: removes "New Chat"-titled empty sessions left
        # over from previous runs.
        try:
            self._history.cleanup_empty()
        except Exception:
            pass
        self._sidebar_visible = False
        self._accumulated_text = ""
        self._response_persisted = False
        self._gate_timer = None
        self._current_asst_bubble: _Bubble | None = None
        self._welcome_widget: QWidget | None = None
        # SIEM alerts view (plugins/chat/siem_alerts.py): a read-only list of
        # the alerts siemgent sent this user, shown in place of a chat.
        self._viewing_alerts = False
        self._alerts_bridge = _AlertBridge()
        self._alerts_bridge.arrived.connect(self._on_alert_arrived)
        siem_alerts.subscribe(self._alerts_bridge.arrived.emit)
        self.reinitialize_client()
        self.status = self.get_status()
        active_id = self._history.get_active_id()
        if active_id:
            saved = self._history.load_messages(active_id)
            if saved:
                if self.base_url:
                    saved = [m for m in saved if m.get("role") != "system"]
                self.conversation_history = saved

    # ===================================================================
    #  Status / client
    # ===================================================================
    def check_status(self):
        if not self.client:
            return "Warning"
        # Access gate: chat is only usable while the endpoint agent runs.
        return "OK" if self._chat_access_status() else "Warning"

    @staticmethod
    def _chat_access_status() -> bool:
        """Return whether the endpoint (SIEM) agent is running.

        The check is "running" (not merely "installed") so that manually
        toggling the SIEM agent off re-locks chat. The VPN is not required.
        """
        try:
            from plugins.wazuh.main import is_agent_running
            return bool(is_agent_running())
        except Exception:
            return False

    def reinitialize_client(self, notify: bool = False):
        """Rebuild the chat client (OpenAI API or Matrix) from settings."""
        self.transport = settings.get("chat", "transport") or "openai"
        if self.transport == "matrix":
            self._init_matrix_client()
            try:
                self._sync_input_enabled()
            except Exception:
                pass
            return
        try:
            from plugins.chat import matrix_transport
            matrix_transport.shutdown_service()
            # SIEM alerts still come over Matrix: keep an alerts-only session.
            matrix_transport.ensure_alerts_listener()
        except Exception:
            pass
        api_key = settings.get_secret("chat", "openai_api_key")
        self.base_url = chat_config.base_url()
        self.session_id = None
        if self.base_url:
            self.model, self.conversation_history = "ministral-3:14b", []
        else:
            self.model = "gpt-4o"
            self.conversation_history = [dict(_SYS_MSG)]
        if not api_key and not self.base_url:
            self.client = None
            return
        try:
            kwargs: dict = {"api_key": api_key or "unused"}
            if self.base_url:
                kwargs["base_url"] = self.base_url
                if self.base_url.lower().startswith("https://"):
                    # Internal root CA for the HTTPS dashboard endpoint.
                    import httpx
                    kwargs["http_client"] = httpx.Client(
                        verify=_tls_verify())
            from openai import OpenAI
            self.client = OpenAI(**kwargs)
        except Exception as e:
            logger.error(f"Chat: client init failed: {e}")
            if notify:
                try:
                    self.app.show_notification(
                        f"Chat Init Error: {e}", type="error")
                except Exception:
                    pass
            self.client = None
        # Reflect any client change in a live screen's input controls.
        try:
            self._sync_input_enabled()
        except Exception:
            pass

    def _init_matrix_client(self) -> None:
        """Matrix transport: the assistant is a bot in an encrypted DM.

        Like the HTTPS agent endpoint, the server keeps the history, so the
        plugin runs in "server-side agent" mode: ``base_url`` is truthy (only
        the new message is sent, no local system prompt) and names the bot.
        """
        from plugins.chat import matrix_transport
        bot = settings.get("chat", "matrix_bot") or matrix_transport.DEFAULT_BOT
        self.base_url = f"matrix:{bot}"
        self.session_id = None
        self.model = "matrix"
        self.conversation_history = []
        self.client = None
        # Why there is no client: shown on the chat screen instead of a guess.
        self._matrix_problem = "unavailable"
        try:
            from plugins.login import oidc
            if not matrix_transport.available():
                logger.error("Chat: Matrix transport selected but matrix-nio[e2e] is not installed")
            elif not oidc.has_session():
                logger.info("Chat: Matrix transport needs a Phoenix sign-in")
                self._matrix_problem = "signin"
            else:
                self.client = matrix_transport.MatrixTransport(bot)
                self._matrix_problem = None
                # Connect now so SIEM alerts arrive without a chat message first.
                matrix_transport.start_background(bot)
        except Exception as e:
            logger.error(f"Chat: Matrix transport init failed: {e}")

    # ===================================================================
    #  Screen construction
    # ===================================================================
    def create_main_screen(self):
        # Access gate: chat is only available while the SIEM/Endpoint agent
        # is RUNNING. A QTimer poller re-checks while the screen is alive, so
        # toggling the agent off snaps chat back to the locked screen — and
        # turning it back on unlocks it — without navigating away and back.
        self._gate_unlocked = self._chat_access_status()
        if not self._gate_unlocked:
            locked = self._build_locked_screen()
            self._start_gate_poller(locked)
            self.second_frame = locked
            return locked

        self._ensure_session()

        root = QWidget()
        root.setObjectName("ChatRoot")
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # -- History drawer (collapsible left panel) --
        self._sidebar = self._build_sidebar()
        self._sidebar.setVisible(self._sidebar_visible)
        outer.addWidget(self._sidebar)

        # -- Chat column (top bar + messages + input) --
        chat_col = QWidget()
        col = QVBoxLayout(chat_col)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        col.addWidget(self._build_top_bar())
        col.addWidget(self._build_message_area(), 1)
        col.addWidget(self._build_input_bar())

        outer.addWidget(chat_col, 1)

        self.second_frame = root
        self._restore_history()
        self._refresh_sidebar()
        self._sync_input_enabled()
        self._start_gate_poller(root)
        return root

    # ---- Access gate -------------------------------------------------------
    def _start_gate_poller(self, owner: QWidget) -> None:
        """Re-check the agent gate every few seconds while chat is shown.

        The QTimer is parented to the screen widget, so it stops and is
        destroyed with the screen — no manual teardown needed.
        """
        timer = QTimer(owner)
        timer.setInterval(4000)

        def _tick():
            unlocked = self._chat_access_status()
            if unlocked == self._gate_unlocked:
                return
            timer.stop()
            if not unlocked:
                # Re-locking mid-stream: persist what we can first.
                try:
                    self._finalize_in_flight_response(persist=True)
                except Exception:
                    pass
            try:
                self.status = self.check_status()
                self.app.update_plugin(self.id)
            except Exception:
                logger.debug("Chat: gate refresh failed")

        timer.timeout.connect(_tick)
        timer.start()
        self._gate_timer = timer

    def _build_locked_screen(self) -> QWidget:
        """Referral screen shown while the access gate is locked."""
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.addStretch(1)

        title = QLabel("Phoenix AI is locked")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size: 20px; font-weight: 700; "
            f"color: {theme.color('text_primary')};")
        lay.addWidget(title)
        lay.addSpacing(8)

        sub = QLabel(
            "Chat is available while the Endpoint agent is running.")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(
            f"font-size: 14px; color: {theme.color('text_secondary')};")
        sub.setWordWrap(True)
        lay.addWidget(sub)
        lay.addSpacing(16)

        row = QLabel("✗  Endpoint agent running")
        row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.setStyleSheet("font-size: 14px; color: #C5221F;")
        lay.addWidget(row)

        lay.addSpacing(16)
        hint = QLabel(
            "Start the Endpoint agent to unlock chat. "
            "This screen unlocks automatically.")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"font-size: 12px; color: {theme.color('text_secondary')};")
        lay.addWidget(hint)
        lay.addStretch(1)
        return page

    # ---- Top bar ----------------------------------------------------------
    def _build_top_bar(self) -> QWidget:
        bar = QFrame()
        bar.setFixedHeight(48)
        bar.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(8)

        self._toggle_btn = self._icon_button("☰")  # hamburger
        self._toggle_btn.clicked.connect(self._toggle_sidebar)
        lay.addWidget(self._toggle_btn)

        lay.addStretch(1)
        title = QLabel("Phoenix AI")
        title.setStyleSheet(
            f"font-size: 16px; font-weight: 700; "
            f"color: {theme.color('text_primary')}; background: transparent;")
        lay.addWidget(title)
        lay.addStretch(1)

        self._new_chat_btn = self._icon_button("+")
        self._new_chat_btn.clicked.connect(self._new_chat)
        lay.addWidget(self._new_chat_btn)
        return bar

    def _icon_button(self, text: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName("Secondary")
        btn.setFixedSize(32, 32)
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setStyleSheet(
            "QPushButton { font-size: 18px; font-weight: 700; padding: 0; "
            "border-radius: 8px; }")
        return btn

    # ---- Message area -----------------------------------------------------
    def _build_message_area(self) -> QWidget:
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        # Thin, minimal scrollbar: 6px, rounded handle, no arrow buttons.
        handle = theme.color("border")
        self._scroll.setStyleSheet(
            "QScrollArea { background: transparent; }"
            "QScrollBar:vertical { background: transparent; width: 6px; "
            "margin: 2px 0; }"
            f"QScrollBar::handle:vertical {{ background: {handle}; "
            f"border-radius: 3px; min-height: 24px; }}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical "
            "{ height: 0; }"
            "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical "
            "{ background: transparent; }")

        self._messages = QWidget()
        self._messages_lay = QVBoxLayout(self._messages)
        self._messages_lay.setContentsMargins(0, 8, 0, 8)
        self._messages_lay.setSpacing(2)
        # Reserved space below the last turn so a freshly-sent user message can
        # always scroll to the top of the viewport (Claude/ChatGPT feel), even
        # when the AI reply is still short. Height is set on each send.
        self._bottom_spacer = QWidget()
        self._bottom_spacer.setFixedHeight(0)
        self._messages_lay.addWidget(self._bottom_spacer)
        self._messages_lay.addStretch(1)  # keeps rows top-packed when sparse
        self._scroll.setWidget(self._messages)
        # Re-fit every bubble's max width when the chat area resizes.
        _orig_resize = self._scroll.resizeEvent

        def _on_scroll_resize(event, _orig=_orig_resize):
            _orig(event)
            self._apply_bubble_widths()

        self._scroll.resizeEvent = _on_scroll_resize
        return self._scroll

    def _bubble_widths(self) -> tuple[int, int]:
        """(user, assistant) max widths for the current viewport size."""
        try:
            avail = self._scroll.viewport().width() - 24  # row margins
        except Exception:
            avail = 0
        if avail <= 0:
            return _USER_MAX, _ASST_MAX
        dyn = int(avail * _BUBBLE_FRACTION)
        return min(_USER_MAX, dyn), min(_ASST_MAX, dyn)

    def _apply_bubble_widths(self) -> None:
        user_w, asst_w = self._bubble_widths()
        lay = getattr(self, "_messages_lay", None)
        if lay is None:
            return
        for i in range(lay.count()):
            w = lay.itemAt(i).widget()
            bubble = getattr(w, "bubble", None)
            if bubble is not None:
                bubble.set_max_width(
                    user_w if bubble._is_user else asst_w)

    # ---- Input bar --------------------------------------------------------
    def _build_input_bar(self) -> QWidget:
        wrap = QFrame()
        wrap.setStyleSheet("background: transparent;")
        outer = QHBoxLayout(wrap)
        outer.setContentsMargins(16, 8, 16, 14)
        outer.setSpacing(0)
        outer.addStretch(1)

        bar = QFrame()
        bar.setObjectName("ChatInputBar")
        bar.setMaximumWidth(900)
        self._input_bar_frame = bar
        self._style_input_bar(focused=False)
        row = QHBoxLayout(bar)
        row.setContentsMargins(8, 6, 8, 6)
        row.setSpacing(6)

        self.chat_entry = _ChatInput()
        self.chat_entry.setPlaceholderText("Message Phoenix AI...")
        self.chat_entry.setStyleSheet(
            "QTextEdit { background: transparent; border: none; "
            "font-size: 15px; padding: 4px 8px; }")
        self.chat_entry.send_requested.connect(self.send_message)
        self.chat_entry.textChanged.connect(self._on_input_changed)
        self.chat_entry.focus_changed.connect(self._set_input_focus_ring)
        self.chat_entry._fit_height()  # re-fit now the stylesheet font is set
        row.addWidget(self.chat_entry, 1)

        self.send_button = QPushButton("↑")
        self.send_button.setFixedSize(36, 36)
        self.send_button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._style_send_button(stop=False)
        self.send_button.clicked.connect(self.send_message)
        # Bottom-align so the button stays anchored while the input grows.
        row.addWidget(self.send_button, 0, Qt.AlignmentFlag.AlignBottom)

        outer.addWidget(bar, 6)
        outer.addStretch(1)
        return wrap

    def _style_input_bar(self, *, focused: bool) -> None:
        """Focus ring: 2px accent border while the input has focus."""
        bg = theme.color("input_bg")
        brd = theme.color("accent") if focused else theme.color("border")
        width = 2 if focused else 1
        self._input_bar_frame.setStyleSheet(
            f"#ChatInputBar {{ background-color: {bg}; "
            f"border: {width}px solid {brd}; border-radius: 22px; }}")

    def _set_input_focus_ring(self, focused: bool) -> None:
        try:
            self._style_input_bar(focused=focused)
        except Exception:
            pass

    def _on_input_changed(self) -> None:
        """Send button: disabled when empty, enabled with content.

        While streaming, the button is the Stop control and stays enabled
        regardless of input content.
        """
        if self._stream_ctrl is not None and self._stream_ctrl.is_active:
            return
        try:
            self.send_button.setEnabled(
                bool(self.chat_entry.text().strip())
                and self.client is not None)
        except Exception:
            pass

    def _style_send_button(self, *, stop: bool) -> None:
        if stop:
            # Smaller square glyph — at 17px the "■" sat below the optical
            # centre and looked pasted-on.
            bg, hover, text = _STOP_RED, _STOP_RED_HOVER, "■"
            size, pad = 13, "0px"
        else:
            # Bigger, semi-bold arrow, nudged up 2px to optically centre it.
            bg, hover, text = BRAND_BLUE, _ACCENT_HOVER, "↑"
            size, pad = 20, "0px 0px 2px 0px"
        self.send_button.setText(text)
        self.send_button.setStyleSheet(
            f"QPushButton {{ background-color: {bg}; color: #ffffff; "
            f"border: none; border-radius: 18px; font-size: {size}px; "
            f"font-weight: 600; padding: {pad}; text-align: center; }}"
            f"QPushButton:hover {{ background-color: {hover}; }}"
            # Disabled = same blue at reduced opacity, not gray — it should
            # still read as the send button, just inactive.
            f"QPushButton:disabled {{ "
            f"background-color: rgba(13, 83, 148, 0.45); "
            f"color: rgba(255, 255, 255, 0.7); }}")

    # ---- History drawer ---------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("ChatSidebar")
        panel.setFixedWidth(_SIDEBAR_WIDTH)
        bg = theme.color("sidebar_bg")
        brd = theme.color("divider")
        panel.setStyleSheet(
            f"#ChatSidebar {{ background-color: {bg}; "
            f"border-right: 1px solid {brd}; }}")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(8, 10, 8, 8)
        lay.setSpacing(6)

        hdr = QHBoxLayout()
        hdr.setContentsMargins(4, 0, 0, 0)
        title = QLabel("HISTORY")
        title.setStyleSheet(
            "font-size: 10px; font-weight: 700; color: #6B7280; "
            "background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch(1)
        new_btn = QPushButton("+ New")
        new_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        new_btn.setStyleSheet(
            f"QPushButton {{ background-color: {BRAND_BLUE}; color: #fff; "
            f"border: none; border-radius: 7px; padding: 5px 10px; "
            f"font-size: 11px; font-weight: 700; }}"
            f"QPushButton:hover {{ background-color: {_ACCENT_HOVER}; }}")
        new_btn.clicked.connect(self._new_chat)
        hdr.addWidget(new_btn)
        lay.addLayout(hdr)

        self._sidebar_scroll = QScrollArea()
        self._sidebar_scroll.setWidgetResizable(True)
        self._sidebar_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._sidebar_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._sidebar_scroll.setStyleSheet("background: transparent;")
        self._sidebar_list = QWidget()
        self._sidebar_list_lay = QVBoxLayout(self._sidebar_list)
        self._sidebar_list_lay.setContentsMargins(0, 0, 0, 0)
        self._sidebar_list_lay.setSpacing(2)
        self._sidebar_list_lay.addStretch(1)
        self._sidebar_scroll.setWidget(self._sidebar_list)
        lay.addWidget(self._sidebar_scroll, 1)
        return panel

    def _refresh_sidebar(self) -> None:
        lay = getattr(self, "_sidebar_list_lay", None)
        if lay is None:
            return
        # Clear existing items (keep the trailing stretch).
        while lay.count() > 1:
            item = lay.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        lay.insertWidget(0, self._alerts_sidebar_item())
        sessions = self._history.list_sessions()
        active_id = (None if getattr(self, "_viewing_alerts", False)
                     else self._history.get_active_id())
        if not sessions:
            empty = QLabel("No conversations")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setStyleSheet(
                "color: #6B7280; font-size: 12px; background: transparent;")
            lay.insertWidget(1, empty)
            return
        for s in sessions:
            lay.insertWidget(
                lay.count() - 1,
                self._sidebar_item(
                    s["id"], s.get("title", "New Chat"),
                    s["id"] == active_id))

    def _sidebar_item(self, sid: str, title: str, active: bool) -> QWidget:
        is_dark = theme.is_dark()
        active_bg = "#1A2F45" if is_dark else "#D6E4F0"
        fg = theme.color("text_primary")
        row = QFrame()
        row.setObjectName("ChatHistoryItem")
        bgrule = f"background-color: {active_bg};" if active else ""
        hover_bg = theme.color("sidebar_hover_bg")
        row.setStyleSheet(
            f"#ChatHistoryItem {{ {bgrule} border-radius: 8px; }}"
            f"#ChatHistoryItem:hover {{ background-color: {hover_bg}; }}")
        # The WHOLE row selects the chat, not just the text label — clicking
        # the padding around the title previously did nothing, which made
        # the drawer feel broken.
        row.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        row.mousePressEvent = lambda _e, s=sid: self._select_chat(s)
        rl = QHBoxLayout(row)
        rl.setContentsMargins(8, 4, 4, 4)
        rl.setSpacing(2)

        lbl = QLabel()
        # Set the font on the WIDGET (not via QSS): elidedText() must use the
        # same metrics the label paints with — the stylesheet font-size isn't
        # reflected in fontMetrics(), which made the elided string ~10px too
        # wide and pushed the delete ✕ past the drawer edge.
        _f = lbl.font()
        _f.setPixelSize(12)
        lbl.setFont(_f)
        lbl.setStyleSheet(f"color: {fg}; background: transparent;")
        # Generous slack: drawer margins + row margins + spacing + the ✕.
        avail = _SIDEBAR_WIDTH - 80
        lbl.setText(lbl.fontMetrics().elidedText(
            title, Qt.TextElideMode.ElideRight, avail))
        lbl.setMaximumWidth(avail)  # hard cap — the ✕ always fits
        lbl.setToolTip(title)
        lbl.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        lbl.mousePressEvent = lambda _e, s=sid: self._select_chat(s)
        rl.addWidget(lbl, 1)

        # Standard close icon from the platform style, NOT a "✕" text glyph —
        # the glyph rendered blank (missing from the active font), which made
        # the delete affordance invisible even though the button was there.
        del_btn = QPushButton()
        del_btn.setIcon(row.style().standardIcon(
            QStyle.StandardPixmap.SP_TitleBarCloseButton))
        del_btn.setIconSize(QSize(12, 12))
        del_btn.setFixedSize(24, 24)
        del_btn.setToolTip("Delete chat")
        del_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        del_btn.setStyleSheet(
            "QPushButton { background: transparent; border: none; "
            "border-radius: 6px; }"
            f"QPushButton:hover {{ background: "
            f"{theme.color('sidebar_hover_bg')}; }}")
        del_btn.clicked.connect(lambda _=False, s=sid: self._delete_chat(s))
        rl.addWidget(del_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _alerts_sidebar_item(self) -> QWidget:
        is_dark = theme.is_dark()
        active_bg = "#1A2F45" if is_dark else "#D6E4F0"
        row = QFrame()
        row.setObjectName("ChatAlertsItem")
        bgrule = f"background-color: {active_bg};" if self._viewing_alerts else ""
        row.setStyleSheet(
            f"#ChatAlertsItem {{ {bgrule} border-radius: 8px; }}"
            f"#ChatAlertsItem:hover {{ background-color: {theme.color('sidebar_hover_bg')}; }}")
        row.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        row.mousePressEvent = lambda _e: self._show_alerts()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(8, 6, 8, 6)
        unread = siem_alerts.store().unread
        lbl = QLabel("🚨  SIEM alerts")
        lbl.setStyleSheet(
            f"color: {theme.color('text_primary')}; font-size: 12px; "
            f"font-weight: 700; background: transparent;")
        rl.addWidget(lbl, 1)
        if unread:
            badge = QLabel(str(unread))
            badge.setStyleSheet(
                f"background-color: {_STOP_RED}; color: #fff; border-radius: 8px; "
                "padding: 1px 6px; font-size: 10px; font-weight: 700;")
            rl.addWidget(badge, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _show_alerts(self) -> None:
        """Replace the conversation with the read-only SIEM alerts list."""
        self._finalize_in_flight_response(persist=True)
        self._save_current_session()
        self._viewing_alerts = True
        self._clear_messages()
        alerts = siem_alerts.store().all()
        if not alerts:
            self._add_assistant_bubble(
                md="**🚨 SIEM alerts**\n\nNo alerts yet. Alerts about machines you own "
                   "will appear here.")
        for alert in alerts:
            self._add_assistant_bubble(md=_alert_markdown(alert))
        siem_alerts.store().mark_read()
        self._refresh_sidebar()
        self._sync_input_enabled()

    _ASK_LIMIT = 8000  # characters of alert text sent with "Ask AI"

    def ask_about_alert(self, body: str) -> bool:
        """Start a new chat asking Phoenix AI about one SIEM alert (the
        Dashboard's alert page). False when the AI is not set up."""
        if self.client is None:
            return False
        if getattr(self, "chat_entry", None) is None:
            return False
        self._new_chat()
        text = (body or "").strip()
        if len(text) > self._ASK_LIMIT:
            text = text[: self._ASK_LIMIT] + "\n…(alert shortened)"
        self._use_suggestion(
            "Explain this Phoenix SIEM alert in plain words: what happened, how "
            "serious it is, and what I should do now.\n\n" + text)
        return True

    def _on_alert_arrived(self, alert: dict) -> None:
        """GUI thread: a new SIEM alert was received."""
        try:
            first = (alert.get("body") or "").strip().splitlines()[0][:120]
        except IndexError:
            first = ""
        try:
            self.app.show_notification(f"🚨 SIEM alert: {first}", type="warning")
        except Exception:
            pass
        try:
            if self._viewing_alerts and getattr(self, "_messages_lay", None) is not None:
                self._add_assistant_bubble(md=_alert_markdown(alert))
                siem_alerts.store().mark_read()
            self._refresh_sidebar()
        except RuntimeError:
            pass  # the chat screen was torn down; the store still has the alert

    def _toggle_sidebar(self) -> None:
        self._sidebar_visible = not self._sidebar_visible
        if getattr(self, "_sidebar", None) is not None:
            self._sidebar.setVisible(self._sidebar_visible)

    # ===================================================================
    #  Welcome screen
    # ===================================================================
    def _restore_history(self) -> None:
        has_history = False
        for msg in self.conversation_history:
            role = msg.get("role")
            content = msg.get("content", "")
            if role == "system":
                continue
            has_history = True
            if role == "user":
                self._add_user_bubble(content)
            elif role == "assistant":
                self._add_assistant_bubble(md=content)
        if has_history:
            return
        if self.client is not None:
            self._welcome_widget = self._build_welcome_screen()
        else:
            self._welcome_widget = self._build_api_missing_screen()
        self._messages_lay.insertWidget(
            self._messages_lay.count() - 1, self._welcome_widget,
            0, Qt.AlignmentFlag.AlignCenter)

    def _clear_welcome(self) -> None:
        if self._welcome_widget is not None:
            self._welcome_widget.setParent(None)
            self._welcome_widget.deleteLater()
            self._welcome_widget = None

    def _build_welcome_screen(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(4)
        lay.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        greeting = QLabel("How can I help you today?")
        greeting.setAlignment(Qt.AlignmentFlag.AlignCenter)
        greeting.setStyleSheet(
            f"font-size: 24px; font-weight: 700; "
            f"color: {theme.color('text_primary')}; background: transparent;")
        lay.addWidget(greeting)

        subtitle = QLabel(
            "Ask about your devices, alerts, vulnerabilities and compliance")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            f"font-size: 14px; color: {theme.color('text_secondary')}; "
            f"background: transparent;")
        lay.addWidget(subtitle)
        lay.addSpacing(14)

        section = QLabel("TRY ASKING")
        section.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: {BRAND_BLUE}; "
            f"background: transparent;")
        lay.addWidget(section)
        lay.addSpacing(8)

        for suggestion in pick_suggestions(4):
            lay.addWidget(self._suggestion_chip(suggestion))
        return w

    def _suggestion_chip(self, text: str) -> QWidget:
        # Card background + visible outline: the previous fill matched the
        # page background in light mode, so the chips read as bare text.
        card_bg = theme.color("card_bg")
        card_hover = theme.color("sidebar_hover_bg")
        chip_fg = theme.color("text_primary")
        chip = QPushButton(f"  ●   {text}")
        chip.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        chip.setMinimumWidth(360)
        chip.setStyleSheet(
            f"QPushButton {{ background-color: {card_bg}; color: {chip_fg}; "
            f"border: 1px solid {theme.color('border')}; "
            f"border-radius: 12px; padding: 12px 16px; "
            f"font-size: 15px; font-weight: 500; text-align: left; }}"
            f"QPushButton:hover {{ background-color: {card_hover}; "
            f"border-color: {theme.color('accent')}; }}")
        chip.clicked.connect(lambda _=False, s=text: self._use_suggestion(s))
        return chip

    def _build_api_missing_screen(self) -> QWidget:
        is_dark = theme.is_dark()
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(6)
        lay.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        icon = QLabel("⚠")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet(
            f"font-size: 36px; color: {'#FBBF24' if is_dark else '#B45309'}; "
            f"background: transparent;")
        lay.addWidget(icon)

        matrix = getattr(self, "transport", "openai") == "matrix"
        signin = getattr(self, "_matrix_problem", None) == "signin"
        title = QLabel(
            ("Sign-in Required" if signin else "Matrix Chat Unavailable")
            if matrix else "API Key Required")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size: 20px; font-weight: 700; "
            f"color: {theme.color('text_primary')}; background: transparent;")
        lay.addWidget(title)

        if not matrix:
            text = "Add an API key in Settings to start chatting."
        elif signin:
            text = "Sign in with your Phoenix account, or switch the transport in Settings."
        else:
            text = "This build lacks Matrix encryption support. Switch the transport in Settings."
        desc = QLabel(text)
        # A word-wrapped label in a centered layout gets a too-small height
        # for its line count (text was clipped); give it room to stay short.
        desc.setMinimumWidth(460)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"font-size: 14px; color: {theme.color('text_secondary')}; "
            f"background: transparent;")
        lay.addWidget(desc)
        lay.addSpacing(12)

        btn = QPushButton("Open Settings")
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.clicked.connect(self._open_settings)
        lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignCenter)
        return w

    # ===================================================================
    #  Bubble helpers
    # ===================================================================
    def _add_user_bubble(self, text: str) -> _Bubble:
        bubble = _Bubble(is_user=True, max_width=self._bubble_widths()[0])
        bubble.set_text(text)
        self._insert_row(_BubbleRow(bubble, is_user=True))
        return bubble

    def _add_assistant_bubble(self, md: str | None = None) -> _Bubble:
        bubble = _Bubble(is_user=False, max_width=self._bubble_widths()[1])
        if md is not None:
            bubble.set_text(md)
        self._insert_row(_BubbleRow(bubble, is_user=False))
        return bubble

    @staticmethod
    def _animations_enabled() -> bool:
        """The Settings 'Disable typing animation' toggle, inverted.

        Governs how response TEXT renders: enabled → stream in as tokens
        arrive; disabled → keep the spinner and show the full response at
        once when it completes. (The spinner itself always animates.)
        Read once per send, not per chunk — settings.get hits disk.
        """
        try:
            return not bool(settings.get("chat", "disable_animation", False))
        except Exception:
            return True

    def apply_animation_setting(self) -> None:
        """Apply the toggle to an in-flight response immediately. Called by
        the Settings plugin on toggle."""
        self._text_anim = self._animations_enabled()
        # Re-enabling mid-stream: flush what has accumulated so the bubble
        # catches up instead of staying on the spinner until the next chunk.
        if (self._text_anim and self._accumulated_text
                and self._current_asst_bubble is not None):
            try:
                self._current_asst_bubble.set_text(
                    self._accumulated_text, streaming=True)
            except Exception:
                pass

    def _insert_row(self, row: QWidget) -> None:
        # Insert above the reserved bottom spacer (and trailing stretch) so
        # rows pack from the top and the spacer always stays last. If the
        # spacer was somehow torn down, recreate it rather than crash.
        try:
            idx = self._messages_lay.indexOf(self._bottom_spacer)
        except RuntimeError:
            idx = -1
        if idx < 0:
            self._bottom_spacer = QWidget()
            self._bottom_spacer.setFixedHeight(0)
            self._messages_lay.insertWidget(
                self._messages_lay.count() - 1, self._bottom_spacer)
            idx = self._messages_lay.indexOf(self._bottom_spacer)
        self._messages_lay.insertWidget(idx, row)

    def _pin_row_to_top(self, row: QWidget) -> None:
        """Scroll so *row* sits at the top of the viewport (Claude-style).

        The bottom spacer is grown to a full viewport height first so the
        row can actually reach the top even when the reply below it is still
        short; the assistant response then streams into the space below.
        """
        def _do() -> None:
            try:
                vp_h = self._scroll.viewport().height()
                self._bottom_spacer.setFixedHeight(vp_h)
                # Let the layout re-run with the enlarged spacer, then scroll.
                QTimer.singleShot(0, lambda: self._apply_pin(row))
            except Exception:
                pass
        QTimer.singleShot(0, _do)

    def _apply_pin(self, row: QWidget) -> None:
        """Smoothly animate the viewport so *row* lands at the top."""
        try:
            bar = self._scroll.verticalScrollBar()
            top = row.mapTo(self._messages, row.rect().topLeft()).y()
            target = min(top, bar.maximum())
            anim = QPropertyAnimation(bar, b"value", self._scroll)
            anim.setDuration(260)
            anim.setStartValue(bar.value())
            anim.setEndValue(target)
            anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
            anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
            self._scroll_anim = anim  # ref: GC'd animations never finish
        except Exception:
            pass

    # ===================================================================
    #  Session management
    # ===================================================================
    def _ensure_session(self) -> None:
        if not self._history.get_active_id():
            self._history.create_session()

    def _save_current_session(self) -> None:
        active_id = self._history.get_active_id()
        if active_id and self.conversation_history:
            self._history.save_messages(active_id, self.conversation_history)

    def _finalize_in_flight_response(self, *, persist: bool = True) -> None:
        """Centralized cancel-and-persist for paths that interrupt a stream.

        The PARTIAL response is discarded and a fixed canned message is
        appended to history instead, exactly once (_response_persisted).
        """
        ctrl = self._stream_ctrl
        if ctrl is not None and ctrl.is_active:
            ctrl.cancel()
        if (persist
                and not getattr(self, "_response_persisted", False)
                and self._current_asst_bubble is not None
                and self._accumulated_text.strip()):
            self.conversation_history.append(
                {"role": "assistant", "content": _NAV_AWAY_MSG})
            self._response_persisted = True
        if self._current_asst_bubble is not None:
            try:
                self._current_asst_bubble.deleteLater()
            except Exception:
                pass
        self._current_asst_bubble = None
        self._accumulated_text = ""
        self._response_persisted = False
        try:
            self._unlock_input()
        except Exception:
            pass

    def _new_chat(self) -> None:
        self._finalize_in_flight_response(persist=True)
        # Don't orphan empty sessions from spammy "+ New" clicks.
        active_id = self._history.get_active_id()
        if active_id and not any(
                m.get("role") == "user"
                for m in self.conversation_history):
            self._history.delete_session(active_id)
        else:
            self._save_current_session()
        self.conversation_history = (
            [] if self.base_url else [dict(_SYS_MSG)])
        self.session_id = None
        self._history.create_session()
        self._rebuild_chat()

    def _select_chat(self, session_id: str) -> None:
        if (session_id == self._history.get_active_id()
                and not getattr(self, "_viewing_alerts", False)):
            return
        self._finalize_in_flight_response(persist=True)
        self._save_current_session()
        messages = self._history.load_messages(session_id)
        self.conversation_history = messages if messages else (
            [] if self.base_url else [dict(_SYS_MSG)])
        self._history.set_active_id(session_id)
        self._rebuild_chat()

    def _delete_chat(self, session_id: str) -> None:
        was_active = session_id == self._history.get_active_id()
        if was_active:
            self._finalize_in_flight_response(persist=False)
        self._history.delete_session(session_id)
        if was_active:
            self.conversation_history = (
                [] if self.base_url else [dict(_SYS_MSG)])
            remaining = self._history.list_sessions()
            if remaining:
                self._select_chat(remaining[0]["id"])
                return
            self._history.create_session()
        self._rebuild_chat()

    def _rebuild_chat(self) -> None:
        """Clear and repopulate the message area for the active session."""
        self._viewing_alerts = False
        self._clear_messages()
        self._restore_history()
        self._refresh_sidebar()
        self._sync_input_enabled()

    def _clear_messages(self) -> None:
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stream_ctrl.cancel()
        self._current_asst_bubble = None
        self._accumulated_text = ""
        self._response_persisted = False
        self._clear_welcome()
        # Remove every message row, but keep the reserved bottom spacer and
        # the trailing stretch. Reset the spacer so a loaded conversation
        # scrolls normally instead of opening with a screen of blank space.
        for i in reversed(range(self._messages_lay.count())):
            w = self._messages_lay.itemAt(i).widget()
            if w is not None and w is not self._bottom_spacer:
                self._messages_lay.takeAt(i)
                w.deleteLater()
        self._bottom_spacer.setFixedHeight(0)

    # ===================================================================
    #  Sending / streaming
    # ===================================================================
    def send_message(self) -> None:
        if self.client is None:
            return
        user_text = self.chat_entry.text().strip()
        if not user_text:
            return
        if len(user_text) > 15000:
            try:
                self.app.show_notification(
                    "Message too long (15,000 character limit).",
                    type="warning")
            except Exception:
                pass
            return
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stop_streaming()
            return
        self._ensure_session()
        self._clear_welcome()
        self.chat_entry.clear()

        user_row = self._add_user_bubble(user_text).parentWidget()
        self._current_asst_bubble = self._add_assistant_bubble()
        # Arrival fades are motion polish, not typing animation — they run
        # regardless of the Settings text-animation toggle.
        try:
            user_row.play_arrival()
            self._current_asst_bubble.parentWidget().play_arrival()
        except Exception:
            pass
        # Pin the just-sent message to the top of the viewport; the reply
        # streams into the reserved space below it.
        self._pin_row_to_top(user_row)
        self.conversation_history.append(
            {"role": "user", "content": user_text})

        self.chat_entry.setEnabled(False)
        self.send_button.setEnabled(True)
        self._style_send_button(stop=True)
        try:
            self.send_button.clicked.disconnect()
        except Exception:
            pass
        self.send_button.clicked.connect(self._stop_streaming)

        self._accumulated_text = ""
        self._response_persisted = False
        self._text_anim = self._animations_enabled()  # per-send snapshot
        self._stream_ctrl = StreamController(
            app=self.app, on_chunk=self._on_stream_chunk,
            on_done=self._on_stream_done, on_error=self._on_stream_error)
        msgs = ([{"role": "user", "content": user_text}]
                if self.base_url else list(self.conversation_history))
        # The server keeps the conversation per session, so every turn of a
        # chat must carry the same id: the local chat id is that id.
        session = self.session_id or self._history.get_active_id()
        extra = ({"session_id": session}
                 if self.base_url and session else None)
        self._last_payload = (msgs, extra)  # kept for error-bubble Retry
        try:
            self._stream_ctrl.start(
                client=self.client, model=self.model, messages=msgs,
                temperature=0.7, extra_body=extra, base_url=self.base_url)
        except Exception as e:
            self._on_stream_error(str(e))

    def _stop_streaming(self) -> None:
        if self._stream_ctrl and self._stream_ctrl.is_active:
            self._stream_ctrl.cancel()
        if self._accumulated_text.strip() and self._current_asst_bubble:
            self._current_asst_bubble.set_text(self._accumulated_text)
            self.conversation_history.append(
                {"role": "assistant", "content": self._accumulated_text})
        elif self._current_asst_bubble is not None:
            self._current_asst_bubble.setParent(None)
            self._current_asst_bubble.deleteLater()
        self._current_asst_bubble = None
        self._unlock_input()
        self._save_current_session()
        self._refresh_sidebar()

    def _on_stream_chunk(self, chunk_text: str) -> None:
        self._accumulated_text += chunk_text
        # Typing animation OFF → leave the spinner up; the full text lands
        # in one go at _on_stream_done.
        if not getattr(self, "_text_anim", True):
            return
        if self._current_asst_bubble is not None:
            self._current_asst_bubble.set_text(
                self._accumulated_text, streaming=True)
        # No auto-scroll here: the user message stays pinned to the top and
        # the reply streams into the reserved space below it. Chasing the
        # bottom on every chunk would yank the view away from what's being
        # read.

    def _on_stream_done(self, full_text: str) -> None:
        if getattr(self, "_response_persisted", False):
            return
        if self._current_asst_bubble is not None:
            if not full_text.strip():
                # Empty SSE: server closed the stream without content. Show a
                # user-facing message instead of a blank bubble, and unlock.
                self._current_asst_bubble.set_text(
                    "No response received from the server. "
                    "Please try again in a moment.")
                self._current_asst_bubble = None
                self._response_persisted = True
                try:
                    self.app.show_notification(
                        "The server returned an empty response.",
                        type="warning")
                except Exception:
                    pass
            else:
                self._current_asst_bubble.set_text(full_text)
                self._current_asst_bubble = None
                self.conversation_history.append(
                    {"role": "assistant", "content": full_text})
                self._response_persisted = True
        self._unlock_input()
        self._save_current_session()
        self._refresh_sidebar()
        # Leave the view where it is — the user message stays pinned near the
        # top with the completed reply below it, matching Claude/ChatGPT.

    def _on_stream_error(self, error_msg: str) -> None:
        if getattr(self, "_response_persisted", False):
            return
        if (self._accumulated_text.strip()
                and self._current_asst_bubble is not None):
            self._current_asst_bubble.set_text(self._accumulated_text)
            self.conversation_history.append(
                {"role": "assistant", "content": self._accumulated_text})
            try:
                self.app.show_notification(
                    "Response may be incomplete.", type="warning")
            except Exception:
                pass
        elif self._current_asst_bubble is not None:
            try:
                bubble = self._current_asst_bubble
                bubble.set_text(f"⚠ {error_msg}")
                row = bubble.parentWidget()
                bubble.add_retry(
                    lambda _=False, r=row: self._retry_after_error(r))
            except Exception:
                pass
        self._current_asst_bubble = None
        self._unlock_input()
        self._save_current_session()

    def _retry_after_error(self, error_row: QWidget) -> None:
        """Replace an error bubble and re-run the failed request."""
        if self.client is None or (
                self._stream_ctrl is not None
                and self._stream_ctrl.is_active):
            return
        payload = getattr(self, "_last_payload", None)
        if not payload:
            return
        try:
            error_row.deleteLater()
        except Exception:
            pass
        self._current_asst_bubble = self._add_assistant_bubble()
        try:
            self._current_asst_bubble.parentWidget().play_arrival()
        except Exception:
            pass
        self.chat_entry.setEnabled(False)
        self.send_button.setEnabled(True)
        self._style_send_button(stop=True)
        try:
            self.send_button.clicked.disconnect()
        except Exception:
            pass
        self.send_button.clicked.connect(self._stop_streaming)
        self._accumulated_text = ""
        self._response_persisted = False
        self._text_anim = self._animations_enabled()
        msgs, extra = payload
        self._stream_ctrl = StreamController(
            app=self.app, on_chunk=self._on_stream_chunk,
            on_done=self._on_stream_done, on_error=self._on_stream_error)
        try:
            self._stream_ctrl.start(
                client=self.client, model=self.model, messages=msgs,
                temperature=0.7, extra_body=extra, base_url=self.base_url)
        except Exception as e:
            self._on_stream_error(str(e))

    def _unlock_input(self) -> None:
        try:
            self.chat_entry.setEnabled(True)
            self._style_send_button(stop=False)
            # Empty input → send stays disabled until the user types.
            self.send_button.setEnabled(
                bool(self.chat_entry.text().strip()))
            try:
                self.send_button.clicked.disconnect()
            except Exception:
                pass
            self.send_button.clicked.connect(self.send_message)
            self.chat_entry.setFocus()
        except Exception:
            pass

    # ===================================================================
    #  Misc
    # ===================================================================
    def _sync_input_enabled(self) -> None:
        """Enable/disable the input controls to match client availability."""
        entry = getattr(self, "chat_entry", None)
        btn = getattr(self, "send_button", None)
        if entry is None or btn is None:
            return
        if getattr(self, "_viewing_alerts", False):
            entry.setEnabled(False)
            entry.setPlaceholderText("SIEM alerts are read-only — pick a chat to talk to Phoenix AI")
            btn.setEnabled(False)
        elif self.client is None:
            entry.setEnabled(False)
            if getattr(self, "transport", "openai") != "matrix":
                hint = "API key required — see Settings"
            elif getattr(self, "_matrix_problem", None) == "signin":
                hint = "Sign in with your Phoenix account to use Matrix chat"
            else:
                hint = "Matrix chat is not available in this build"
            entry.setPlaceholderText(hint)
            btn.setEnabled(False)
        else:
            entry.setEnabled(True)
            entry.setPlaceholderText("Message Phoenix AI...")
            # Disabled-when-empty: only enable if there's content to send.
            btn.setEnabled(bool(entry.text().strip()))

    def _use_suggestion(self, text: str) -> None:
        if self.client is None:
            return
        self.chat_entry.setText(text)
        self.send_message()

    def _open_settings(self) -> None:
        try:
            sp = next((p for p in self.app.plugin_list
                       if p.get_name() == "Settings"), None)
            if sp:
                self.app.select_frame_by_name(
                    "frame_Settings", button=sp.get_button())
        except Exception:
            pass

    def on_theme_changed(self) -> None:
        """Rebuild the chat screen — the drawer, top bar and bubbles resolve
        theme colours at build time, so a mode toggle otherwise leaves the
        history drawer (and friends) painted in the previous mode."""
        try:
            self._save_current_session()
        except Exception:
            pass
        try:
            self.app.update_plugin(self.id)
        except Exception:
            logger.debug("Chat: theme rebuild failed")

    def destroy(self) -> None:
        """Plugin teardown — cancel any in-flight stream and flush state."""
        bridge = getattr(self, "_alerts_bridge", None)
        if bridge is not None:
            siem_alerts.unsubscribe(bridge.arrived.emit)
        try:
            self._finalize_in_flight_response(persist=True)
        except Exception:
            pass
        try:
            self._save_current_session()
        except Exception:
            pass
