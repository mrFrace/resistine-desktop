"""
Unit tests for plugins/chat/main.py — Chat Plugin (PyQt6) logic.

The OpenAI SDK client and httpx.Client are replaced with mocks; no network.
Widget tests build the real chat screen under an offscreen QApplication with
the endpoint-agent access gate forced open, and replace StreamController so
the request a send would make can be inspected.

Covers:
- check_status: client + access gate
- reinitialize_client (OpenAI transport): default/custom base URL, API key
  handling, TLS http_client for HTTPS, init failure, session/history reset
- send_message: guards, history append, payload (server-side session mode)
- stream callbacks: done / empty / error persist correctly
- StreamController end-to-end against a mocked OpenAI stream
- _new_chat / _delete_chat: session reset (replaces old _clear_conversation)
"""
import os
import time
from unittest.mock import MagicMock

import pytest

from plugins.chat import main as chat_main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def openai_cls(monkeypatch):
    """Replace openai.OpenAI and httpx.Client so client init never networks."""
    import httpx
    import openai

    cls = MagicMock(name="OpenAI")
    monkeypatch.setattr(openai, "OpenAI", cls)
    monkeypatch.setattr(httpx, "Client", MagicMock(name="httpx.Client"))
    monkeypatch.setattr(chat_main, "_tls_verify", lambda: "/ca.pem")
    return cls


@pytest.fixture()
def plugin(isolated_settings, openai_cls):
    """Chat Plugin on the default (OpenAI-compatible) transport."""
    from plugins.chat.main import Plugin
    return Plugin(MagicMock())


@pytest.fixture()
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def stream_cls(monkeypatch):
    """Capture StreamController construction/start instead of streaming."""
    cls = MagicMock(name="StreamController")
    cls.return_value.is_active = False
    monkeypatch.setattr(chat_main, "StreamController", cls)
    return cls


@pytest.fixture()
def screen(qapp, plugin, stream_cls, monkeypatch):
    """The live chat screen with the access gate open."""
    monkeypatch.setattr(chat_main.Plugin, "_chat_access_status",
                        staticmethod(lambda: True))
    root = plugin.create_main_screen()
    yield plugin
    root.deleteLater()


def _send(p, text):
    p.chat_entry.setText(text)
    p.send_message()


# ===========================================================================
# check_status
# ===========================================================================
@pytest.mark.unit
class TestCheckStatus:
    def test_returns_warning_when_client_is_none(self, plugin):
        plugin.client = None
        assert plugin.check_status() == "Warning"

    def test_ok_when_client_set_and_agent_running(self, plugin, monkeypatch):
        monkeypatch.setattr(chat_main.Plugin, "_chat_access_status",
                            staticmethod(lambda: True))
        plugin.client = MagicMock()
        assert plugin.check_status() == "OK"

    def test_warning_when_agent_not_running(self, plugin, monkeypatch):
        monkeypatch.setattr(chat_main.Plugin, "_chat_access_status",
                            staticmethod(lambda: False))
        plugin.client = MagicMock()
        assert plugin.check_status() == "Warning"

    def test_access_follows_wazuh_agent_running(self, monkeypatch):
        from plugins.wazuh import main as wz
        monkeypatch.setattr(wz, "is_agent_running", lambda: True)
        assert chat_main.Plugin._chat_access_status() is True
        monkeypatch.setattr(wz, "is_agent_running", lambda: False)
        assert chat_main.Plugin._chat_access_status() is False


# ===========================================================================
# reinitialize_client (OpenAI-compatible transport)
# ===========================================================================
@pytest.mark.unit
class TestReinitializeClient:
    def test_default_base_url_without_api_key(self, plugin, openai_cls):
        """No settings at all → default HTTPS endpoint, placeholder key, CA bundle."""
        openai_cls.reset_mock()
        plugin.reinitialize_client()
        assert plugin.transport == "openai"
        assert plugin.base_url == chat_main._DEFAULT_BASE_URL
        assert plugin.client is openai_cls.return_value
        kwargs = openai_cls.call_args.kwargs
        assert kwargs["api_key"] == "unused"
        assert kwargs["base_url"] == chat_main._DEFAULT_BASE_URL
        assert "http_client" in kwargs

    def test_https_endpoint_uses_tls_verify_bundle(self, plugin, openai_cls):
        import httpx
        httpx.Client.reset_mock()
        plugin.reinitialize_client()
        httpx.Client.assert_called_once_with(verify="/ca.pem")
        assert openai_cls.call_args.kwargs["http_client"] is httpx.Client.return_value

    def test_api_key_and_plain_http_url_forwarded(self, plugin, isolated_settings, openai_cls):
        url = "http://localhost:11434/v1"
        isolated_settings.set("chat", "openai_base_url", url)
        isolated_settings.set_secret("chat", "openai_api_key", "sk-local")
        plugin.reinitialize_client()
        kwargs = openai_cls.call_args.kwargs
        assert kwargs == {"api_key": "sk-local", "base_url": url}  # no http_client
        assert plugin.base_url == url

    def test_server_side_mode_resets_model_history_and_session(self, plugin):
        plugin.session_id = "old-session-abc"
        plugin.model = "something"
        plugin.conversation_history = [{"role": "user", "content": "x"}]
        plugin.reinitialize_client()
        assert plugin.session_id is None
        assert plugin.model == "ministral-3:14b"
        # The server keeps the conversation: no local system prompt.
        assert plugin.conversation_history == []

    def test_empty_base_url_setting_falls_back_to_default(self, plugin, isolated_settings):
        isolated_settings.set("chat", "openai_base_url", "")
        plugin.reinitialize_client()
        assert plugin.base_url == chat_main._DEFAULT_BASE_URL

    def test_init_failure_sets_client_none(self, plugin, openai_cls):
        openai_cls.side_effect = Exception("invalid key format")
        plugin.reinitialize_client()
        assert plugin.client is None
        plugin.app.show_notification.assert_not_called()

    def test_init_failure_notifies_when_requested(self, plugin, openai_cls):
        openai_cls.side_effect = Exception("boom")
        plugin.reinitialize_client(notify=True)
        assert plugin.client is None
        msg = plugin.app.show_notification.call_args
        assert "boom" in msg.args[0]
        assert msg.kwargs["type"] == "error"

    def test_openai_transport_shuts_down_matrix_service(self, plugin, monkeypatch):
        from plugins.chat import matrix_transport
        shutdown, listener = MagicMock(), MagicMock()
        monkeypatch.setattr(matrix_transport, "shutdown_service", shutdown)
        monkeypatch.setattr(matrix_transport, "ensure_alerts_listener", listener)
        plugin.reinitialize_client()
        shutdown.assert_called_once()
        listener.assert_called_once()


# ===========================================================================
# send_message
# ===========================================================================
@pytest.mark.unit
class TestSendMessage:
    def test_no_client_is_noop(self, screen, stream_cls):
        screen.client = None
        _send(screen, "Hello?")
        stream_cls.return_value.start.assert_not_called()
        assert not any(m["role"] == "user" for m in screen.conversation_history)

    def test_blank_message_is_noop(self, screen, stream_cls):
        _send(screen, "   ")
        stream_cls.return_value.start.assert_not_called()

    def test_too_long_message_rejected(self, screen, stream_cls):
        _send(screen, "x" * 15001)
        stream_cls.return_value.start.assert_not_called()
        msg = screen.app.show_notification.call_args
        assert "15,000" in msg.args[0] and msg.kwargs["type"] == "warning"

    def test_user_message_appended_and_input_cleared(self, screen):
        _send(screen, "  My question  ")
        assert screen.conversation_history[-1] == {"role": "user", "content": "My question"}
        assert screen.chat_entry.text() == ""
        assert not screen.chat_entry.isEnabled()  # locked while streaming

    def test_server_side_mode_sends_only_new_message_with_session(self, screen, stream_cls):
        screen.conversation_history = [
            {"role": "user", "content": "earlier"},
            {"role": "assistant", "content": "reply"},
        ]
        _send(screen, "test message")
        kw = stream_cls.return_value.start.call_args.kwargs
        assert kw["messages"] == [{"role": "user", "content": "test message"}]
        assert kw["client"] is screen.client
        assert kw["model"] == "ministral-3:14b"
        assert kw["base_url"] == chat_main._DEFAULT_BASE_URL
        # The local chat id doubles as the server-side session id.
        active = screen._history.get_active_id()
        assert active
        assert kw["extra_body"] == {"session_id": active}

    def test_explicit_session_id_wins(self, screen, stream_cls):
        screen.session_id = "existing-session-123"
        _send(screen, "hello")
        kw = stream_cls.return_value.start.call_args.kwargs
        assert kw["extra_body"] == {"session_id": "existing-session-123"}

    def test_local_mode_sends_full_history_without_extra_body(self, screen, stream_cls):
        """If no server-side base_url is in effect, the whole history is sent."""
        screen.base_url = None
        screen.conversation_history = [dict(chat_main._SYS_MSG)]
        _send(screen, "hi")
        kw = stream_cls.return_value.start.call_args.kwargs
        assert kw["messages"] == [dict(chat_main._SYS_MSG), {"role": "user", "content": "hi"}]
        assert kw["extra_body"] is None

    def test_start_failure_routes_to_error_bubble(self, screen, stream_cls):
        stream_cls.return_value.start.side_effect = RuntimeError("no route")
        _send(screen, "hi")
        assert screen.conversation_history[-1]["role"] == "user"
        assert screen.chat_entry.isEnabled()
        assert screen._current_asst_bubble is None


# ===========================================================================
# Stream callbacks
# ===========================================================================
@pytest.mark.unit
class TestStreamCallbacks:
    def test_done_appends_and_persists_assistant_reply(self, screen):
        _send(screen, "q")
        screen._on_stream_chunk("Part1")
        screen._on_stream_chunk("Part2")
        assert screen._accumulated_text == "Part1Part2"
        screen._on_stream_done("Part1Part2")
        assert screen.conversation_history[-1] == {"role": "assistant", "content": "Part1Part2"}
        saved = screen._history.load_messages(screen._history.get_active_id())
        assert saved[-2:] == [{"role": "user", "content": "q"},
                              {"role": "assistant", "content": "Part1Part2"}]
        assert screen.chat_entry.isEnabled()

    def test_done_is_idempotent(self, screen):
        _send(screen, "q")
        screen._on_stream_done("A")
        screen._on_stream_done("A")
        assert [m["role"] for m in screen.conversation_history].count("assistant") == 1

    def test_empty_response_not_stored(self, screen):
        _send(screen, "q")
        screen._on_stream_done("   ")
        assert screen.conversation_history[-1]["role"] == "user"
        assert screen.app.show_notification.call_args.kwargs["type"] == "warning"

    def test_error_without_text_keeps_no_assistant_message(self, screen):
        _send(screen, "q")
        screen._on_stream_error("Could not reach host")
        assert screen.conversation_history[-1]["role"] == "user"
        assert screen._last_payload[0] == [{"role": "user", "content": "q"}]

    def test_error_after_partial_text_keeps_partial(self, screen):
        _send(screen, "q")
        screen._on_stream_chunk("partial")
        screen._on_stream_error("reset")
        assert screen.conversation_history[-1] == {"role": "assistant", "content": "partial"}

    def test_stop_streaming_keeps_partial_and_cancels(self, screen, stream_cls):
        _send(screen, "q")
        stream_cls.return_value.is_active = True
        screen._on_stream_chunk("half")
        screen._stop_streaming()
        stream_cls.return_value.cancel.assert_called_once()
        assert screen.conversation_history[-1] == {"role": "assistant", "content": "half"}


# ===========================================================================
# StreamController against a mocked OpenAI stream
# ===========================================================================
def _openai_client():
    # spec: an OpenAI SDK client has no stream_deltas (that marks a transport)
    return MagicMock(spec=["chat"])


def _chunk(content):
    c = MagicMock()
    c.choices = [MagicMock()]
    c.choices[0].delta.content = content
    return c


@pytest.mark.unit
class TestStreamControllerOpenAI:
    def _run(self, client, **start_kw):
        from plugins.chat.streaming import StreamController
        chunks, done, errors = [], [], []
        ctrl = StreamController(app=MagicMock(), on_chunk=chunks.append,
                                on_done=done.append, on_error=errors.append)
        ctrl.start(client=client, model="m", messages=[{"role": "user", "content": "hi"}],
                   **start_kw)
        deadline = time.monotonic() + 5
        while ctrl.is_active and time.monotonic() < deadline:
            ctrl._poll()
            time.sleep(0.01)
        return chunks, done, errors

    def test_chunks_assembled_and_empty_deltas_skipped(self):
        client = _openai_client()
        client.chat.completions.create.return_value = iter(
            [_chunk("Hello"), _chunk(None), _chunk(""), _chunk(" world")])
        chunks, done, errors = self._run(client, extra_body={"session_id": "s1"})
        assert "".join(chunks) == "Hello world"
        assert done == ["Hello world"]
        assert errors == []
        kw = client.chat.completions.create.call_args.kwargs
        assert kw["stream"] is True and kw["model"] == "m"
        assert kw["extra_body"] == {"session_id": "s1"}

    def test_api_error_reported_with_endpoint_and_key_redacted(self):
        client = _openai_client()
        client.chat.completions.create.side_effect = RuntimeError("bad key sk-SECRET123")
        _, done, errors = self._run(client, base_url="http://h/v1")
        assert done == []
        assert len(errors) == 1
        assert "sk-SECRET123" not in errors[0] and "sk-***" in errors[0]
        assert "http://h/v1" in errors[0]


# ===========================================================================
# New / delete chat (replaces the removed _clear_conversation)
# ===========================================================================
@pytest.mark.unit
class TestNewChat:
    def test_new_chat_resets_history_and_session(self, screen):
        _send(screen, "old msg")
        screen._on_stream_done("old reply")
        old_id = screen._history.get_active_id()
        screen.session_id = "old-session-xyz"

        screen._new_chat()

        assert screen.conversation_history == []  # server-side mode: no system prompt
        assert screen.session_id is None
        new_id = screen._history.get_active_id()
        assert new_id and new_id != old_id
        # The previous conversation was kept.
        assert screen._history.load_messages(old_id)[-1]["content"] == "old reply"

    def test_new_chat_on_empty_session_discards_it(self, screen):
        empty_id = screen._history.get_active_id()
        screen._new_chat()
        ids = [s["id"] for s in screen._history.list_sessions()]
        assert empty_id not in ids
        assert screen._history.get_active_id() in ids

    def test_new_chat_cancels_in_flight_stream(self, screen, stream_cls):
        _send(screen, "q")
        stream_cls.return_value.is_active = True
        screen._on_stream_chunk("partial")
        screen._new_chat()
        stream_cls.return_value.cancel.assert_called()
        assert screen._current_asst_bubble is None

    def test_delete_active_chat_selects_remaining(self, screen):
        _send(screen, "first")
        screen._on_stream_done("r1")
        first_id = screen._history.get_active_id()
        screen._new_chat()
        second_id = screen._history.get_active_id()

        screen._delete_chat(second_id)

        assert screen._history.get_active_id() == first_id
        assert screen.conversation_history[-1]["content"] == "r1"


# ---------------------------------------------------------------------------
# SIEM alerts view (plugins/chat/siem_alerts.py)
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestSiemAlertsView:
    @pytest.fixture(autouse=True)
    def _fresh_store(self, monkeypatch):
        from plugins.chat import siem_alerts
        monkeypatch.setattr(siem_alerts, "_store", None)
        monkeypatch.setattr(siem_alerts, "_listeners", [])

    def _rows(self, p):
        return [p._messages_lay.itemAt(i).widget() for i in range(p._messages_lay.count())
                if p._messages_lay.itemAt(i).widget() is not None
                and p._messages_lay.itemAt(i).widget() is not p._bottom_spacer]

    def test_alerts_view_is_read_only_and_lists_alerts(self, screen):
        from plugins.chat import siem_alerts
        siem_alerts.store().add({"event_id": "$1", "body": "Failed login on AnubisAI", "ts": 1.0})
        screen._show_alerts()
        assert screen._viewing_alerts
        assert not screen.chat_entry.isEnabled() and not screen.send_button.isEnabled()
        assert len(self._rows(screen)) == 1
        assert siem_alerts.store().unread == 0

    def test_a_new_alert_appears_while_viewing(self, screen):
        screen._show_alerts()                       # empty -> one placeholder bubble
        screen._on_alert_arrived({"event_id": "$2", "body": "x", "ts": 2.0})
        assert len(self._rows(screen)) == 2
        screen.app.show_notification.assert_called()

    def test_picking_a_chat_leaves_the_alerts_view(self, screen):
        screen._show_alerts()
        screen._select_chat(screen._history.get_active_id())
        assert not screen._viewing_alerts
        assert screen.chat_entry.isEnabled()
