"""Matrix chat transport: turn assembly, turn collection, controller + plugin wiring."""

import queue
import threading
from unittest.mock import MagicMock

import pytest

from plugins.chat import matrix_transport as mt
from plugins.chat.matrix_transport import (
    TURN_KEY,
    MatrixTransport,
    MatrixTransportError,
    TurnAssembler,
    classify,
)

PROMPT = "$prompt"
REPLY = "$reply"


def reply(body, status="running", **turn):
    return {"msgtype": "m.text", "body": body,
            "m.relates_to": {"m.in_reply_to": {"event_id": PROMPT}},
            TURN_KEY: {"status": status, "tools": [], **turn}}


def edit(body, status="running", **turn):
    new = {"msgtype": "m.text", "body": body, TURN_KEY: {"status": status, "tools": [], **turn}}
    return {"msgtype": "m.text", "body": "* " + body, "m.new_content": new,
            "m.relates_to": {"rel_type": "m.replace", "event_id": REPLY}}


@pytest.mark.unit
class TestClassify:
    def test_reply_and_edit(self):
        assert classify(reply("a"), PROMPT, None) == "reply"
        assert classify(edit("a"), PROMPT, REPLY) == "edit"

    def test_unrelated_events_ignored(self):
        assert classify(reply("a"), "$other", None) is None
        assert classify(edit("a"), PROMPT, None) is None  # edit before its reply is known
        assert classify({"body": "hi"}, PROMPT, REPLY) is None


@pytest.mark.unit
class TestTurnAssembler:
    def test_growing_versions_become_deltas(self):
        asm = TurnAssembler()
        assert asm.feed(reply("> Running **x**...\n")) == "> Running **x**...\n"
        assert asm.feed(edit("> Running **x**...\nHello")["m.new_content"]) == "Hello"
        assert not asm.done
        assert asm.feed(edit("> Running **x**...\nHello world", "final")["m.new_content"]) == " world"
        assert asm.done and asm.status == "final"

    def test_error_status_carries_message(self):
        asm = TurnAssembler()
        assert asm.feed(reply("You are not enrolled", "error", error="You are not enrolled")) == ""
        assert asm.status == "error" and asm.error == "You are not enrolled"

    def test_non_extension_is_dropped(self):
        asm = TurnAssembler()
        asm.feed(reply("abc"))
        assert asm.feed(edit("xyz")["m.new_content"]) == ""
        assert asm.text == "abc"

    def test_reply_without_turn_key_is_final(self):
        asm = TurnAssembler()
        assert asm.feed({"body": "plain"}) == "plain"
        assert asm.done

    def test_parts_continue_the_answer(self):
        asm = TurnAssembler()
        assert asm.feed(reply("CVE-1 steps\n\n")) == "CVE-1 steps\n\n"
        assert asm.feed(reply("CVE-2", part=1)) == "CVE-2"
        assert asm.feed(edit("CVE-2 steps")["m.new_content"] | {TURN_KEY: {"status": "running", "part": 1}}) == " steps"
        assert asm.feed(reply("CVE-3", "final", part=2)) == "CVE-3"
        assert asm.text == "CVE-1 steps\n\nCVE-2 stepsCVE-3"
        assert asm.done and asm.status == "final"

    def test_late_version_of_earlier_part_is_ignored(self):
        asm = TurnAssembler()
        asm.feed(reply("part one\n"))
        asm.feed(reply("part two", part=1))
        assert asm.feed(reply("part one\nlate", part=0)) == ""
        assert asm.text == "part one\npart two"

    def test_error_after_parts_ends_turn(self):
        asm = TurnAssembler()
        asm.feed(reply("part one\n"))
        asm.feed(reply("⚠️ The answer could not be delivered in full.", "error", part=1,
                       error="The answer could not be delivered in full."))
        assert asm.status == "error" and "delivered" in asm.error


class FakeService:
    def __init__(self, typing=False):
        self.typing = typing

    def bot_typing(self):
        return self.typing


def collect(events, cancel=None, service=None):
    q = queue.Queue()
    for e in events:
        q.put(e)
    t = MatrixTransport.__new__(MatrixTransport)
    t.bot = "@secagent:hs"
    return list(t._collect(service or FakeService(), q, PROMPT, cancel or threading.Event()))


@pytest.mark.unit
class TestCollect:
    def test_full_turn(self):
        out = collect([
            ("message", "$noise", {"body": "old message"}),
            ("message", REPLY, reply("Hi")),
            ("message", "$e1", edit("Hi there")),
            ("message", "$e2", edit("Hi there!", "final")),
            ("message", "$late", edit("Hi there! more")),  # after final: never read
        ])
        assert out == ["Hi", " there", "!"]

    def test_answer_split_into_parts(self):
        def part_edit(event_id, body, status="running", part=1):
            new = {"msgtype": "m.text", "body": body,
                   TURN_KEY: {"status": status, "tools": [], "part": part}}
            return {"body": "* " + body, "m.new_content": new,
                    "m.relates_to": {"rel_type": "m.replace", "event_id": event_id}}

        out = collect([
            ("message", REPLY, reply("First CVE.")),
            ("message", "$e1", edit("First CVE.\n\n")),  # part 0 sealed
            ("message", "$p1", reply("Second", part=1)),
            ("message", "$e2", part_edit("$p1", "Second CVE.")),
            ("message", "$e3", part_edit("$p1", "Second CVE. Done.", "final")),
        ])
        assert "".join(out) == "First CVE.\n\nSecond CVE. Done."

    def test_error_reply_raises_user_message(self):
        with pytest.raises(MatrixTransportError, match="not enrolled"):
            collect([("message", "$n", reply("You are not enrolled.", "error", error="You are not enrolled."))])

    def test_undecryptable_reply_raises(self):
        with pytest.raises(MatrixTransportError, match="decrypt"):
            collect([("undecryptable", "$x", {})])

    def test_no_answer_times_out(self, monkeypatch):
        monkeypatch.setattr(mt, "_FIRST_REPLY_TIMEOUT", 0.3)
        with pytest.raises(MatrixTransportError, match="did not answer"):
            collect([])

    def test_cancel_stops_quietly(self):
        cancel = threading.Event()
        cancel.set()
        assert collect([("message", REPLY, reply("Hi"))], cancel=cancel) == []


def key_check(published_ed25519):
    """Run _ensure_device_keys_published against a fake client."""
    import asyncio

    from nio import KeysQueryResponse

    svc = mt.MatrixService("https://hs", "@me:hs", "DEV", "@bot:hs")
    client = MagicMock()
    client.olm.account.shared = True
    client.olm.account.identity_keys = {"ed25519": "OURS"}
    client.olm.users_for_key_query = set()
    devices = {} if published_ed25519 is None else {
        "DEV": {"keys": {"ed25519:DEV": published_ed25519}}}

    async def keys_query():
        return KeysQueryResponse({"@me:hs": devices}, {})

    async def keys_upload():
        pass

    client.keys_query = keys_query
    client.keys_upload = MagicMock(side_effect=keys_upload)
    svc._client = client
    asyncio.run(svc._ensure_device_keys_published())
    return client


@pytest.mark.unit
class TestDeviceKeyRepublish:
    def test_keys_on_server_left_alone(self):
        client = key_check("OURS")
        assert client.olm.account.shared is True
        client.keys_upload.assert_not_called()

    @pytest.mark.parametrize("published", [None, "STALE"])
    def test_missing_or_stale_keys_reuploaded(self, published):
        # Revoked session → device (and its keys) deleted server-side.
        client = key_check(published)
        assert client.olm.account.shared is False
        client.keys_upload.assert_called_once()


@pytest.mark.unit
class TestStreamControllerTransport:
    def test_transport_deltas_reach_queue_then_done(self):
        from plugins.chat.streaming import StreamController

        class T:
            def describe(self):
                return "fake"

            def stream_deltas(self, text, session, cancel):
                assert text == "list my agents" and session == "abc123"
                yield "one "
                yield "two"

        ctrl = StreamController(MagicMock(), MagicMock(), MagicMock(), MagicMock())
        ctrl._worker_transport(T(), [{"role": "user", "content": "list my agents"}], {"session_id": "abc123"})
        items = []
        while not ctrl._queue.empty():
            items.append(ctrl._queue.get_nowait())
        assert [i for i in items if i[0] == "chunk"] == [("chunk", "one "), ("chunk", "two")]
        assert items[-1][0] == "done"

    def test_transport_error_becomes_error_message(self):
        from plugins.chat.streaming import StreamController

        class T:
            def describe(self):
                return "fake"

            def stream_deltas(self, text, session, cancel):
                raise MatrixTransportError("You are not enrolled.")
                yield  # pragma: no cover

        ctrl = StreamController(MagicMock(), MagicMock(), MagicMock(), MagicMock())
        ctrl._worker_transport(T(), [{"role": "user", "content": "x"}], None)
        assert ctrl._queue.get_nowait() == ("error", "You are not enrolled.")


@pytest.mark.unit
class TestPluginTransportSelection:
    def _plugin(self, monkeypatch, signed_in):
        from plugins.login import oidc
        from utils import settings

        settings.set("chat", "transport", "matrix")
        settings.set("auth", "user_id", "@francis:phoenix.exposed")
        monkeypatch.setattr(oidc, "has_session", lambda: signed_in)
        from plugins.chat.main import Plugin
        return Plugin(MagicMock())

    def test_matrix_transport_when_signed_in(self, isolated_settings, monkeypatch):
        p = self._plugin(monkeypatch, True)
        assert isinstance(p.client, MatrixTransport)
        assert p.base_url == "matrix:@secagent:phoenix.exposed"
        assert p.conversation_history == []

    def test_matrix_without_sign_in_has_no_client(self, isolated_settings, monkeypatch):
        p = self._plugin(monkeypatch, False)
        assert p.client is None and p.transport == "matrix"

    def test_custom_bot_id(self, isolated_settings, monkeypatch):
        from utils import settings

        settings.set("chat", "matrix_bot", "@bot:example.org")
        p = self._plugin(monkeypatch, True)
        assert p.client.bot == "@bot:example.org"

    def test_switching_back_to_openai(self, isolated_settings, monkeypatch):
        from plugins.chat import matrix_transport
        from utils import settings

        p = self._plugin(monkeypatch, True)
        listener = MagicMock()
        monkeypatch.setattr(matrix_transport, "ensure_alerts_listener", listener)
        settings.set("chat", "transport", "openai")
        p.reinitialize_client()
        assert p.transport == "openai"
        assert not isinstance(p.client, MatrixTransport)
        listener.assert_called_once()  # SIEM alerts keep arriving over Matrix


@pytest.fixture()
def qapp():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.mark.unit
class TestSettingsTransportCard:
    def _card(self, qapp):
        from plugins.settings.main import Plugin
        p = Plugin(MagicMock(plugin_list=[]))
        p._test_card = p._api_card()  # keep the parent widget alive
        return p

    def test_switch_to_matrix_saves_transport_and_bot(self, isolated_settings, qapp):
        from utils import settings

        p = self._card(qapp)
        assert p.transport_combo.currentData() == "openai"
        assert p.matrix_bot_entry.isHidden() and not p.api_base_entry.isHidden()
        p.transport_combo.setCurrentIndex(p.transport_combo.findData("matrix"))
        assert p.api_base_entry.isHidden() and not p.matrix_bot_entry.isHidden()
        p.matrix_bot_entry.setText("@bot:example.org")
        p.save_api_key()
        assert settings.get("chat", "transport") == "matrix"
        assert settings.get("chat", "matrix_bot") == "@bot:example.org"

    def test_default_bot_is_not_persisted(self, isolated_settings, qapp):
        from utils import settings

        p = self._card(qapp)
        p.transport_combo.setCurrentIndex(p.transport_combo.findData("matrix"))
        p.save_api_key()
        assert settings.get("chat", "matrix_bot") is None

    def test_invalid_bot_id_rejected(self, isolated_settings, qapp):
        from utils import settings

        p = self._card(qapp)
        p.transport_combo.setCurrentIndex(p.transport_combo.findData("matrix"))
        p.matrix_bot_entry.setText("secagent")
        p.save_api_key()
        assert settings.get("chat", "transport") is None
        assert "Matrix ID" in p.status_label.text()


@pytest.mark.unit
class TestMatrixUnavailableReason:
    def test_missing_e2ee_is_not_reported_as_sign_in(self, isolated_settings, monkeypatch):
        from plugins.login import oidc
        from utils import settings

        settings.set("chat", "transport", "matrix")
        monkeypatch.setattr(oidc, "has_session", lambda: True)
        monkeypatch.setattr(mt, "available", lambda: False)
        from plugins.chat.main import Plugin
        p = Plugin(MagicMock())
        assert p.client is None and p._matrix_problem == "unavailable"

    def test_signed_out_reports_sign_in(self, isolated_settings, monkeypatch):
        from plugins.login import oidc
        from utils import settings

        settings.set("chat", "transport", "matrix")
        monkeypatch.setattr(oidc, "has_session", lambda: False)
        monkeypatch.setattr(mt, "available", lambda: True)
        from plugins.chat.main import Plugin
        p = Plugin(MagicMock())
        assert p.client is None and p._matrix_problem == "signin"
