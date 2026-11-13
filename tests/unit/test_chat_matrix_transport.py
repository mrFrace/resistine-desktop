"""Matrix chat transport: turn assembly, turn collection, controller + plugin wiring."""

import os
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

    def test_size_cap_truncates_with_marker(self, monkeypatch):
        monkeypatch.setattr(mt, "_MAX_TURN_TEXT", 10)
        asm = TurnAssembler()
        assert asm.feed(reply("abcdefghijKLM")) == "abcdefghij" + mt._TRUNCATED_MARKER
        assert asm.truncated and asm.text == "abcdefghij" + mt._TRUNCATED_MARKER
        # No more text is accepted after the cap...
        assert asm.feed(edit("abcdefghijKLMNOP")["m.new_content"]) == ""
        assert asm.text == "abcdefghij" + mt._TRUNCATED_MARKER
        # ...but the turn can still end.
        asm.feed(edit("abcdefghijKLMNOPQ", "final")["m.new_content"])
        assert asm.done and asm.status == "final"

    def test_part_cap_truncates_with_marker(self, monkeypatch):
        monkeypatch.setattr(mt, "_MAX_TURN_PARTS", 2)
        asm = TurnAssembler()
        asm.feed(reply("a"))
        asm.feed(reply("b", part=1))
        assert asm.feed(reply("c", part=2)) == mt._TRUNCATED_MARKER
        assert asm.truncated and asm.text == "ab" + mt._TRUNCATED_MARKER
        assert asm.feed(reply("d", part=3)) == ""
        assert asm.feed(reply("e", "final", part=4)) == ""
        assert asm.done and asm.status == "final"

    def test_marker_emitted_once(self, monkeypatch):
        monkeypatch.setattr(mt, "_MAX_TURN_TEXT", 4)
        asm = TurnAssembler()
        asm.feed(reply("abcdef"))
        assert asm.feed(edit("abcdefgh")["m.new_content"]) == ""
        assert asm.text.count(mt._TRUNCATED_MARKER) == 1


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


@pytest.mark.unit
class TestOnMessageRequiresDecryption:
    """A compromised homeserver can forge ``sender`` on plaintext events, so
    only Megolm-decrypted room messages reach the turn queue or SIEM alerts."""

    def _service(self):
        svc = mt.MatrixService.__new__(mt.MatrixService)
        svc.room_id = "!dm:hs"
        svc.bot = "@secagent:hs"
        svc.alerts_bot = "@siem:hs"
        svc._alert_rooms = {"!alerts:hs"}
        svc._turn_q = queue.Queue()
        return svc

    def _event(self, sender, decrypted):
        e = MagicMock()
        e.sender = sender
        e.decrypted = decrypted
        e.event_id = "$evt"
        e.body = "body"
        e.server_timestamp = 1
        e.source = {"content": {"body": "body"}}
        return e

    def _room(self, room_id):
        r = MagicMock()
        r.room_id = room_id
        return r

    def _run(self, svc, room, event):
        import asyncio
        asyncio.run(svc._on_message(room, event))

    def test_plaintext_bot_message_dropped(self):
        svc = self._service()
        self._run(svc, self._room("!dm:hs"), self._event("@secagent:hs", False))
        assert svc._turn_q.empty()

    def test_decrypted_bot_message_queued(self):
        svc = self._service()
        self._run(svc, self._room("!dm:hs"), self._event("@secagent:hs", True))
        kind, event_id, content = svc._turn_q.get_nowait()
        assert kind == "message" and content == {"body": "body"}

    def test_plaintext_alert_not_published(self, monkeypatch):
        publish = MagicMock()
        monkeypatch.setattr(mt.siem_alerts, "publish", publish)
        svc = self._service()
        self._run(svc, self._room("!alerts:hs"), self._event("@siem:hs", False))
        publish.assert_not_called()

    def test_decrypted_alert_published(self, monkeypatch):
        publish = MagicMock()
        monkeypatch.setattr(mt.siem_alerts, "publish", publish)
        svc = self._service()
        self._run(svc, self._room("!alerts:hs"), self._event("@siem:hs", True))
        publish.assert_called_once_with("!alerts:hs", "$evt", "body", 1)


def key_check(published_ed25519, shared=True):
    """Run _ensure_device_keys_published against a fake client."""
    import asyncio

    from nio import KeysQueryResponse

    svc = mt.MatrixService("https://hs", "@me:hs", "DEV", "@bot:hs")
    client = MagicMock()
    client.olm.account.shared = shared
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
class TestStoreFileNames:
    """nio names its store files after the user ID, whose ':' breaks Windows."""

    USER, DEVICE = "@me:phoenix.exposed", "PHX_DEV"

    def open_store(self, tmp_path, monkeypatch, platform):
        pytest.importorskip("nio.store")
        monkeypatch.setattr(mt.sys, "platform", platform)
        store = mt._store_class()(self.USER, self.DEVICE, str(tmp_path), "pickle")
        # A first send marks the bot's devices ignored: that replaces a trust file.
        store.ignore_db._save()
        store.database.close()
        return sorted(p.name for p in tmp_path.iterdir())

    def test_windows_names_have_no_colon(self, tmp_path, monkeypatch):
        names = self.open_store(tmp_path, monkeypatch, "win32")
        assert names == ["@me_phoenix.exposed_PHX_DEV.db",
                         "@me_phoenix.exposed_PHX_DEV.ignored_devices"]

    def test_other_platforms_keep_nio_names(self, tmp_path, monkeypatch):
        names = self.open_store(tmp_path, monkeypatch, "linux")
        assert names == ["@me:phoenix.exposed_PHX_DEV.db",
                         "@me:phoenix.exposed_PHX_DEV.ignored_devices"]


from cryptography.fernet import Fernet  # noqa: E402

_FERNET = Fernet(Fernet.generate_key())


@pytest.mark.unit
class TestStoreKey:
    """A store key that won't decrypt must not be replaced while the keyring
    itself may be at fault: a new key locks the E2EE store for good."""

    def test_made_once_then_reused(self, isolated_settings):
        key = mt._store_key()
        assert key and mt._store_key() == key

    def test_locked_keyring_keeps_the_stored_key(self, isolated_settings, monkeypatch):
        isolated_settings.set_secret("auth", "refresh_token", "rt")
        isolated_settings.set_secret("chat", "matrix_store_key", "the-real-key")
        stored = isolated_settings.get("chat", "matrix_store_key")
        monkeypatch.setattr(isolated_settings, "get_secret", lambda ns, k: None)  # nothing decrypts
        with pytest.raises(MatrixTransportError, match="keyring"):
            mt._store_key()
        assert isolated_settings.get("chat", "matrix_store_key") == stored  # untouched

    def test_lost_key_is_replaced_when_the_master_key_works(self, isolated_settings):
        isolated_settings.set_secret("auth", "refresh_token", "rt")
        isolated_settings.set("chat", "matrix_store_key", "ENC:written-under-another-master-key")
        key = mt._store_key()
        assert key and isolated_settings.get_secret("chat", "matrix_store_key") == key

    def test_key_lives_in_the_keyring(self, isolated_settings, mock_keyring):
        _, kr = mock_keyring
        key = mt._store_key()
        assert kr[(isolated_settings.MATRIX_STORE_KEY_SERVICE,
                   isolated_settings.MATRIX_STORE_KEY_USERNAME)] == key

    def test_clobbered_chat_json_copy_does_not_lose_the_key(self, isolated_settings, mock_keyring):
        """What reset the store: chat.json's copy turned up encrypted under
        another master key. The keyring entry still has the key."""
        isolated_settings.set_secret("auth", "refresh_token", "rt")
        key = mt._store_key()
        isolated_settings.set("chat", "matrix_store_key", "ENC:written-under-another-master-key")
        assert mt._store_key() == key
        assert isolated_settings.get_secret("chat", "matrix_store_key") == key  # copy repaired

    def test_older_versions_key_moves_to_the_keyring(self, isolated_settings, mock_keyring):
        _, kr = mock_keyring
        isolated_settings.set_secret("chat", "matrix_store_key", "old-key")
        assert mt._store_key() == "old-key"
        assert "old-key" in kr.values()

    def test_no_keyring_falls_back_to_chat_json(self, isolated_settings, monkeypatch):
        kr = isolated_settings.keyring
        monkeypatch.setattr(kr, "get_password", lambda *a: (_ for _ in ()).throw(RuntimeError("no dbus")))
        monkeypatch.setattr(kr, "set_password", lambda *a: (_ for _ in ()).throw(RuntimeError("no dbus")))
        monkeypatch.setattr(isolated_settings, "_get_fernet", lambda: _FERNET)  # the master key
        key = mt._store_key()
        assert key and mt._store_key() == key

    def test_store_key_mismatch_is_recognised(self):
        class LibolmPickleException(Exception):
            pass
        msg = "The pickle couldn't be decrypted: The MAC of the ciphertext didn't pass validation"
        assert mt._is_store_key_mismatch(LibolmPickleException(msg))
        assert mt._is_store_key_mismatch(RuntimeError(msg))
        assert not mt._is_store_key_mismatch(RuntimeError("connection refused"))

    def test_unreadable_store_is_moved_aside_not_deleted(self, tmp_path):
        prefix = mt._store_prefix("@me:phoenix.exposed", "DEV")
        for name in (f"{prefix}.db", f"{prefix}.trusted_devices", "@other:x_DEV2.db"):
            (tmp_path / name).write_text("x")
        dest = mt._set_store_aside(str(tmp_path), "@me:phoenix.exposed", "DEV")
        assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == ["@other:x_DEV2.db"]
        assert sorted(os.listdir(dest)) == [f"{prefix}.db", f"{prefix}.trusted_devices"]


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

    @pytest.mark.parametrize("published", [None, "STALE"])
    def test_new_store_left_to_normal_upload(self, published):
        # Fresh crypto store under a reused device ID: the regular
        # keys_upload in _main publishes (and replaces) the keys.
        client = key_check(published, shared=False)
        assert client.olm.account.shared is False
        client.keys_upload.assert_not_called()


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
        p.transport_combo.setCurrentIndex(p.transport_combo.findData("openai"))
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


@pytest.mark.unit
class TestPostToAlertsRoom:
    """The Dashboard's weekly sentence goes to the alerts room over the
    running session; nothing is started for it."""

    def _service(self, running=True, rooms=("!a:hs", "!b:hs")):
        svc = mt.MatrixService.__new__(mt.MatrixService)
        svc.room_id = None
        svc._alert_rooms = set(rooms)
        svc._error = None
        svc._ready = threading.Event()
        svc._ready.set()
        svc.is_running = lambda: running
        svc.sent = []

        def run_coro(coro, timeout):
            coro.close()  # the coroutine itself is exercised in test_send_text_checks_the_room
            svc.sent.append(timeout)
            return "$evt"
        svc.run_coro = run_coro
        svc.send_text = lambda room_id, text: _record(svc, room_id, text)
        return svc

    def test_no_session_or_no_room(self, monkeypatch, isolated_settings):
        monkeypatch.setattr(mt, "_service", None)
        assert mt.post_to_alerts_room("hi") is False
        monkeypatch.setattr(mt, "_service", self._service(running=False))
        assert mt.post_to_alerts_room("hi") is False
        monkeypatch.setattr(mt, "_service", self._service())
        assert mt.post_to_alerts_room("hi") is False  # no alert room known in settings

    def test_posts_to_the_room_that_spoke_last(self, monkeypatch, isolated_settings, tmp_path):
        from plugins.chat import siem_alerts
        svc = self._service()
        monkeypatch.setattr(mt, "_service", svc)
        store = siem_alerts.AlertStore(str(tmp_path / "a.json"))
        monkeypatch.setattr(siem_alerts, "store", lambda: store)
        siem_alerts.add_alert_room("!a:hs")
        siem_alerts.add_alert_room("!b:hs")
        siem_alerts.add_alert_room("!stale:hs")  # known in settings, not in this session
        assert mt.post_to_alerts_room("hi") is True
        assert svc.calls == [("!a:hs", "hi")]
        store.add({"room_id": "!b:hs", "event_id": "$1", "body": "x", "ts": 10})
        store.add({"room_id": "!stale:hs", "event_id": "$2", "body": "x", "ts": 20})
        assert mt.post_to_alerts_room("again") is True
        assert svc.calls[-1] == ("!a:hs", "again")  # the stale room's alert doesn't count
        store.add({"room_id": "!b:hs", "event_id": "$3", "body": "x", "ts": 30})
        assert mt.post_to_alerts_room("third") is True
        assert svc.calls[-1] == ("!b:hs", "third")

    def test_send_failure_is_false_not_raised(self, monkeypatch, isolated_settings):
        from plugins.chat import siem_alerts
        svc = self._service()
        svc.run_coro = MagicMock(side_effect=mt.MatrixTransportError("down"))
        svc.send_text = lambda room_id, text: None  # nothing to await: run_coro fails first
        monkeypatch.setattr(mt, "_service", svc)
        siem_alerts.add_alert_room("!a:hs")
        assert mt.post_to_alerts_room("hi") is False

    def test_send_text_checks_the_room(self):
        import asyncio
        svc = mt.MatrixService.__new__(mt.MatrixService)
        svc.room_id = "!dm:hs"
        svc._alert_rooms = {"!a:hs"}
        with pytest.raises(mt.MatrixTransportError):
            asyncio.run(svc.send_text("!other:hs", "hi"))


def _record(svc, room_id, text):
    svc.__dict__.setdefault("calls", []).append((room_id, text))

    async def coro():
        return "$evt"
    return coro()
