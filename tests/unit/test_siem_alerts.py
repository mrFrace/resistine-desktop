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
