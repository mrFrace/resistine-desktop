"""SIEM alerts over Matrix: which invites are accepted, the alert store, and the
MatrixService routing of alert-room messages away from the chat turn."""

import asyncio
from types import SimpleNamespace

import pytest

from plugins.chat import matrix_transport as mt
from plugins.chat import siem_alerts

ME = "@francis:phoenix.exposed"
BOT = siem_alerts.ALERTS_BOT_DEFAULT


def _invite(sender, state_key=ME, membership="invite"):
    return [{"type": "m.room.create", "state_key": "", "sender": sender, "content": {}},
            {"type": "m.room.member", "state_key": state_key, "sender": sender,
             "content": {"membership": membership}}]


@pytest.fixture
def fresh(tmp_config_dir, monkeypatch):
    monkeypatch.setattr(siem_alerts, "_store", None)
    monkeypatch.setattr(siem_alerts, "_listeners", [])
    return tmp_config_dir


@pytest.mark.unit
class TestInvites:
    def test_only_the_alerts_bot_is_accepted(self):
        assert siem_alerts.is_alert_invite(_invite(BOT), ME, BOT)
        assert not siem_alerts.is_alert_invite(_invite("@mallory:phoenix.exposed"), ME, BOT)

    def test_an_invite_for_someone_else_is_not_ours(self):
        assert not siem_alerts.is_alert_invite(_invite(BOT, state_key="@drake:phoenix.exposed"), ME, BOT)

    def test_no_invite_event(self):
        assert not siem_alerts.is_alert_invite([], ME, BOT)
        assert not siem_alerts.is_alert_invite(_invite(BOT, membership="join"), ME, BOT)

    def test_alert_rooms_persist(self, fresh):
        siem_alerts.add_alert_room("!a:phoenix.exposed")
        siem_alerts.add_alert_room("!a:phoenix.exposed")
        assert siem_alerts.alert_rooms() == ["!a:phoenix.exposed"]


@pytest.mark.unit
class TestStore:
    def test_publish_dedupes_by_event_id_and_counts_unread(self, fresh):
        seen = []
        siem_alerts.subscribe(seen.append)
        assert siem_alerts.publish("!r", "$1", "alert one", 1_000_000)
        assert not siem_alerts.publish("!r", "$1", "alert one", 1_000_000)  # re-synced on restart
        assert siem_alerts.publish("!r", "$2", "alert two")
        assert [a["body"] for a in seen] == ["alert one", "alert two"]
        assert siem_alerts.store().unread == 2
        siem_alerts.store().mark_read()
        assert siem_alerts.store().unread == 0

    def test_store_survives_a_restart_and_is_capped(self, fresh):
        for i in range(siem_alerts.MAX_ALERTS + 5):
            siem_alerts.publish("!r", f"${i}", f"a{i}")
        again = siem_alerts.AlertStore()
        assert len(again.all()) == siem_alerts.MAX_ALERTS
        assert again.all()[-1]["body"] == f"a{siem_alerts.MAX_ALERTS + 4}"

    def test_a_failing_listener_does_not_stop_the_others(self, fresh):
        seen = []
        siem_alerts.subscribe(lambda a: 1 / 0)
        siem_alerts.subscribe(seen.append)
        siem_alerts.publish("!r", "$x", "body")
        assert len(seen) == 1


def _service(fresh_rooms=("!alerts:phoenix.exposed",)):
    for r in fresh_rooms:
        siem_alerts.add_alert_room(r)
    svc = mt.MatrixService("https://hs", ME, "DEV", "@secagent:phoenix.exposed")
    svc.room_id = "!assistant:phoenix.exposed"
    return svc


def _ev(sender, eid="$e", body="hello"):
    return SimpleNamespace(sender=sender, event_id=eid, body=body, server_timestamp=1_700_000_000_000,
                           source={"content": {"body": body}})


@pytest.mark.unit
class TestService:
    def test_sync_filter_includes_alert_rooms(self, fresh):
        svc = _service()
        assert svc._sync_filter()["room"]["rooms"] == ["!assistant:phoenix.exposed",
                                                       "!alerts:phoenix.exposed"]

    def test_alert_message_is_published_not_queued_as_a_chat_turn(self, fresh):
        svc = _service()
        q = svc.begin_turn()
        asyncio.run(svc._on_message(SimpleNamespace(room_id="!alerts:phoenix.exposed"), _ev(BOT)))
        assert q.empty()
        assert [a["body"] for a in siem_alerts.store().all()] == ["hello"]

    def test_someone_else_in_an_alert_room_is_ignored(self, fresh):
        svc = _service()
        asyncio.run(svc._on_message(SimpleNamespace(room_id="!alerts:phoenix.exposed"),
                                    _ev("@mallory:phoenix.exposed")))
        assert siem_alerts.store().all() == []

    def test_the_assistant_turn_still_works(self, fresh):
        svc = _service()
        q = svc.begin_turn()
        asyncio.run(svc._on_message(SimpleNamespace(room_id="!assistant:phoenix.exposed"),
                                    _ev("@secagent:phoenix.exposed", "$reply")))
        assert q.get_nowait()[1] == "$reply"

    def test_undecryptable_alert_is_shown_as_such(self, fresh):
        svc = _service()
        asyncio.run(svc._on_undecryptable(SimpleNamespace(room_id="!alerts:phoenix.exposed"),
                                          _ev(BOT, "$u")))
        assert siem_alerts.store().all()[0]["body"] == siem_alerts.UNDECRYPTABLE


# --------------------------------------------------------------------------- rooms joined elsewhere

def _state(creator=BOT, encrypted=True):
    evs = [{"type": "m.room.create", "state_key": "", "sender": creator, "content": {}}]
    if encrypted:
        evs.append({"type": "m.room.encryption", "state_key": "", "sender": creator,
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"}})
    return evs


@pytest.mark.unit
class TestJoinedElsewhere:
    def test_room_created_by_the_bot_and_encrypted_is_an_alert_room(self):
        assert siem_alerts.is_alert_room(_state(), BOT)

    @pytest.mark.parametrize("state", [
        _state(creator="@mallory:phoenix.exposed"),   # someone else's room
        _state(encrypted=False),                       # plaintext: never trusted
        [{"type": "m.room.create", "state_key": "x", "sender": BOT}],  # not the create event
        [], None,
    ])
    def test_other_rooms_are_not(self, state):
        assert not siem_alerts.is_alert_room(state, BOT)

    def test_no_bot_configured_matches_nothing(self):
        assert not siem_alerts.is_alert_room(_state(creator=""), "")

    def test_service_adopts_only_bot_rooms(self, fresh):
        svc = mt.MatrixService("https://hs", ME, "DEV", None)
        svc._adopt_joined_alert_rooms({
            "!alerts:hs": {"state": {"events": _state()}},
            "!friends:hs": {"state": {"events": _state(creator="@alice:hs")}},
            "!weird:hs": None,
        })
        assert svc._alert_rooms == {"!alerts:hs"}
        assert siem_alerts.alert_rooms() == ["!alerts:hs"]
        assert siem_alerts.alert_room_since("!alerts:hs") is not None
        assert svc._full_state_next

    def test_since_is_kept_from_the_first_time(self, fresh):
        siem_alerts.add_alert_room("!a:hs", since=100.0)
        siem_alerts.add_alert_room("!a:hs", since=200.0)
        assert siem_alerts.alert_room_since("!a:hs") == 100.0
        assert siem_alerts.alert_room_since("!other:hs") is None


@pytest.mark.unit
class TestOldUndecryptable:
    def test_alerts_from_before_this_device_are_skipped(self, fresh):
        siem_alerts.add_alert_room("!alerts:phoenix.exposed", since=1_800_000_000.0)
        svc = mt.MatrixService("https://hs", ME, "DEV", None)
        old = _ev(BOT, "$old")  # 1_700_000_000 s: before since
        new = SimpleNamespace(**{**vars(_ev(BOT, "$new")), "server_timestamp": 1_800_000_100_000})
        room = SimpleNamespace(room_id="!alerts:phoenix.exposed")
        asyncio.run(svc._on_undecryptable(room, old))
        asyncio.run(svc._on_undecryptable(room, new))
        assert [a["event_id"] for a in siem_alerts.store().all()] == ["$new"]

    def test_readable_old_alerts_are_still_shown(self, fresh):
        siem_alerts.add_alert_room("!alerts:phoenix.exposed", since=1_800_000_000.0)
        svc = mt.MatrixService("https://hs", ME, "DEV", None)
        asyncio.run(svc._on_message(SimpleNamespace(room_id="!alerts:phoenix.exposed"), _ev(BOT, "$old")))
        assert siem_alerts.store().all()[0]["body"] == "hello"


# --------------------------------------------------------------------------- alerts-only service

@pytest.mark.unit
class TestAlertsOnly:
    def test_filter_syncs_only_alert_rooms(self, fresh):
        svc = mt.MatrixService("https://hs", ME, "DEV", None)
        assert svc.alerts_only
        assert svc._sync_filter()["room"]["rooms"] == []  # nothing until one is known
        svc._alert_rooms.add("!alerts:hs")
        assert svc._sync_filter()["room"]["rooms"] == ["!alerts:hs"]

    def test_alerts_only_transport_never_streams(self, fresh):
        t = mt.MatrixTransport(None)
        t.user_id = ME
        with pytest.raises(mt.MatrixTransportError):
            next(t.stream_deltas("hi", None, __import__("threading").Event()))


@pytest.fixture
def no_service(monkeypatch):
    monkeypatch.setattr(mt, "_service", None)
    monkeypatch.setattr(mt, "_retired", None)
    monkeypatch.setattr(mt, "_alerts_started", 0.0)


@pytest.mark.unit
class TestServiceFactory:
    def test_alerts_only_reuses_a_chat_service(self, no_service):
        chat = mt._get_service("https://hs", ME, "DEV", "@secagent:hs")
        assert mt._get_service("https://hs", ME, "DEV", None) is chat

    def test_chat_replaces_alerts_only_and_waits_for_it(self, no_service):
        alerts = mt._get_service("https://hs", ME, "DEV", None)
        chat = mt._get_service("https://hs", ME, "DEV", "@secagent:hs")
        assert chat is not alerts and alerts._stopping
        assert chat._predecessor is alerts  # shares the E2EE store: opened only after it ends

    def test_after_shutdown_the_next_service_waits_too(self, no_service):
        old = mt._get_service("https://hs", ME, "DEV", "@secagent:hs")
        mt.shutdown_service()
        assert mt._get_service("https://hs", ME, "DEV", None)._predecessor is old


@pytest.mark.unit
class TestEnsureAlertsListener:
    @pytest.fixture
    def env(self, fresh, no_service, monkeypatch):
        from plugins.login import oidc
        from utils import settings
        settings.set("auth", "user_id", ME)
        settings.set("auth", "device_id", "DEV")
        monkeypatch.setattr(oidc, "homeserver_url", lambda: "https://hs")
        monkeypatch.setattr(mt, "available", lambda: True)
        started = []
        monkeypatch.setattr(mt.MatrixService, "ensure_ready", lambda self, timeout=0: started.append(self))
        return oidc, started

    def _wait(self, started, n):
        import time
        for _ in range(100):
            if len(started) >= n:
                return
            time.sleep(0.01)

    def test_signed_out_does_nothing(self, env, monkeypatch):
        oidc, started = env
        monkeypatch.setattr(oidc, "has_session", lambda: False)
        mt.ensure_alerts_listener()
        assert mt._service is None and started == []

    def test_signed_in_starts_alerts_only_once(self, env, monkeypatch):
        oidc, started = env
        monkeypatch.setattr(oidc, "has_session", lambda: True)
        mt.ensure_alerts_listener()
        self._wait(started, 1)
        assert len(started) == 1 and started[0].alerts_only
        mt.ensure_alerts_listener()  # within the restart window: no second start
        import time
        time.sleep(0.05)
        assert len(started) == 1

    def test_restart_after_the_window(self, env, monkeypatch):
        oidc, started = env
        monkeypatch.setattr(oidc, "has_session", lambda: True)
        mt.ensure_alerts_listener()
        self._wait(started, 1)
        monkeypatch.setattr(mt, "_alerts_started", 1.0)  # long ago
        mt.ensure_alerts_listener()
        self._wait(started, 2)
        assert len(started) == 2
