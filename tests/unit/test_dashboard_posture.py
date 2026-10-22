"""Security posture panel (plugins/dashboard/posture.py): fetching the
signed-in user's cards from /v1/me/posture and turning them into rows.
No network: the API helper is mocked."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from plugins.dashboard import posture
from plugins.vpn import provisioning as prov

NOW = datetime(2026, 10, 12, 23, 0)


def card(hostname="francispc", grade="F", score=57, computed="2026-10-12T22:50:31", **kw):
    c = {
        "schema": "phoenix.posture.v1", "agent_id": "004", "hostname": hostname, "os": "Ubuntu",
        "computed_at": computed, "score": score, "grade": grade, "health": "at_risk",
        "vulnerabilities": {"total": 3868, "critical": 226, "high": 1434, "medium": 251, "low": 47},
        "compliance": {"score_pct": 96, "failed_checks": 8, "checks": 218},
        "alerts": {"window_hours": 24, "critical": 0, "high": 2, "available": True},
        "recommendations": ["Patch 226 critical vulnerabilities", "Address 1434 high-severity vulnerabilities",
                            "Remediate 8 failed CIS/SCA checks", "Fourth"],
    }
    c.update(kw)
    return c


def response(status=200, body=None, etag=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body if body is not None else {}
    r.headers = {"ETag": etag} if etag else {}
    return r


@pytest.fixture
def signed_in(isolated_settings, monkeypatch):
    isolated_settings.set("auth", "logged_in", True)
    calls = []
    answers = []

    def fake_request(method, path, **kw):
        calls.append((method, path, kw.get("headers") or {}))
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(prov, "_authorized_request", fake_request)
    monkeypatch.setitem(posture._last, "tried_at", 0.0)
    monkeypatch.setitem(posture._last, "status", None)
    return calls, answers


# --------------------------------------------------------------------------- fetch

@pytest.mark.unit
class TestFetch:
    def test_caches_cards_and_etag(self, signed_in, isolated_settings):
        calls, answers = signed_in
        answers.append(response(200, {"user_id": "francis", "agents": [card(), {"schema": "other"}]}, '"e1"'))
        st = posture.fetch()
        assert st["status"] == "ok" and [c["hostname"] for c in st["cards"]] == ["francispc"]
        assert calls == [("GET", "/v1/me/posture", {})]
        assert isolated_settings.get("dashboard", "posture")["etag"] == '"e1"'

    def test_sends_etag_and_keeps_cache_on_304(self, signed_in):
        calls, answers = signed_in
        answers += [response(200, {"agents": [card()]}, 'W/"e1"'), response(304)]
        posture.fetch()
        st = posture.fetch(force=True)
        assert calls[1][2] == {"If-None-Match": 'W/"e1"'}
        assert st["status"] == "not_modified" and len(st["cards"]) == 1

    def test_throttled(self, signed_in):
        calls, answers = signed_in
        answers.append(response(200, {"agents": [card()]}))
        posture.fetch()
        posture.fetch()
        assert len(calls) == 1

    def test_not_enrolled_clears_cache(self, signed_in):
        calls, answers = signed_in
        answers += [response(200, {"agents": [card()]}), response(403, {"detail": "not enrolled"})]
        posture.fetch()
        st = posture.fetch(force=True)
        assert st["status"] == "not_enrolled" and st["cards"] == []

    def test_error_keeps_last_known(self, signed_in):
        calls, answers = signed_in
        answers += [response(200, {"agents": [card()]}), prov.ProvisioningError("offline")]
        posture.fetch()
        st = posture.fetch(force=True)
        assert st["status"] == "error" and st["error"] == "offline" and len(st["cards"]) == 1

    def test_signed_out_makes_no_request(self, isolated_settings, monkeypatch):
        isolated_settings.set("auth", "logged_in", False)
        monkeypatch.setattr(prov, "_authorized_request", lambda *a, **k: pytest.fail("no request when signed out"))
        assert posture.fetch(force=True)["status"] == "signed_out"


# --------------------------------------------------------------------------- panel rows

def st(status="ok", cards=None, error=None):
    return {"status": status, "cards": [card()] if cards is None else cards, "error": error}


@pytest.mark.unit
class TestPanelData:
    def test_this_machine_first_with_grade_badge(self):
        cards = [card("briareosai", "A", 99), card(), card("AnubisAI", "B", 86)]
        d = posture.panel_data(st(cards=cards), {"francispc"}, NOW)
        assert d["badge"] == ("error", "Grade F")
        rows = d["rows"]
        assert rows["Machine"] == "francispc"
        assert rows["Score"] == "F · 57/100, at risk"
        assert rows["Vulnerabilities"] == "226 critical · 1,434 high"
        assert rows["Compliance"] == "96% (8 failed checks)"
        assert rows["Alerts (24 h)"] == "0 critical · 2 high"
        assert rows["Updated"] == "Less than an hour ago"
        assert rows["To do"].count("\n") == 2  # top 3 only
        assert rows["Other machines"] == "briareosai: A · 99\nAnubisAI: B · 86"

    @pytest.mark.parametrize("grade,kind", [("A", "ok"), ("B", "ok"), ("C", "warning"), ("D", "error")])
    def test_badge_follows_grade(self, grade, kind):
        assert posture.panel_data(st(cards=[card(grade=grade)]), {"francispc"}, NOW)["badge"] == (kind, f"Grade {grade}")

    @pytest.mark.parametrize("reason,text", [
        ("not_covered", "Not scanned: the SIEM has no vulnerability feed for this OS"),
        ("unavailable", "Unavailable: the last scan failed"),
    ])
    def test_no_vulnerability_scan_is_not_zero_vulnerabilities(self, reason, text):
        nixos = card("AnubisAI", "B", 88, vulnerabilities={"total": 0, "critical": 0, "high": 0,
                                                             "available": False, "reason": reason})
        d = posture.panel_data(st(cards=[nixos]), {"anubisai"}, NOW)
        assert d["badge"] == ("warning", "Grade B, partial")
        assert d["rows"]["Vulnerabilities"] == text

    def test_stale_after_a_missed_daily_run(self):
        d = posture.panel_data(st(cards=[card(computed="2026-10-11T06:00:00")]), {"francispc"}, NOW)
        assert d["badge"] == ("warning", "Stale") and d["rows"]["Updated"] == "1 day ago"

    def test_never_shows_another_machine_as_this_one(self):
        d = posture.panel_data(st(cards=[card("briareosai", "A", 99)]), {"francispc"}, NOW)
        assert d["badge"] == ("info", "No data for this machine")
        assert "Machine" not in d["rows"] and d["rows"]["Other machines"] == "briareosai: A · 99"

    def test_hostname_match_is_case_insensitive(self):
        assert posture.panel_data(st(cards=[card("FrancisPC")]), {"francispc"}, NOW)["rows"]["Machine"] == "FrancisPC"

    def test_states_without_cards(self):
        assert posture.panel_data(st("signed_out", []), set(), NOW)["badge"] == ("info", "Sign in")
        assert posture.panel_data(st("not_enrolled", []), set(), NOW)["badge"] == ("info", "Not enrolled")
        assert posture.panel_data(st("error", [], "offline"), set(), NOW)["rows"]["Posture"] == "offline"
        assert posture.panel_data(st("ok", []), set(), NOW)["badge"] == ("info", "No data")
        assert posture.panel_data(st(None, []), set(), NOW) is None  # still loading

    def test_error_with_cache_says_it_is_last_known(self):
        d = posture.panel_data(st("error", None, "offline"), {"francispc"}, NOW)
        assert d["badge"] == ("error", "Grade F") and "last known" in d["rows"]["Note"]


@pytest.mark.unit
def test_api_helper_merges_extra_headers(monkeypatch):
    from plugins.login import oidc

    http = MagicMock()
    http.request.return_value = response(304)
    monkeypatch.setattr(oidc, "_session", lambda: http)
    monkeypatch.setattr(oidc, "refresh", lambda force=False: "tok")
    prov._authorized_request("GET", "/v1/me/posture", headers={"If-None-Match": '"e1"'})
    headers = http.request.call_args.kwargs["headers"]
    assert headers == {"If-None-Match": '"e1"', "Authorization": "Bearer tok"}
