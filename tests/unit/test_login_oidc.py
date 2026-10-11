"""Unit tests for plugins/login/oidc.py (Phoenix / MAS sign-in) against a fake MAS."""

import threading
import time
import urllib.parse
import urllib.request
from unittest.mock import MagicMock

import pytest

from plugins.login import oidc

ISSUER = "https://auth.example.test/"
META = {
    "issuer": ISSUER,
    "authorization_endpoint": ISSUER + "authorize",
    "token_endpoint": ISSUER + "oauth2/token",
    "registration_endpoint": ISSUER + "oauth2/registration",
    "device_authorization_endpoint": ISSUER + "oauth2/device",
    "revocation_endpoint": ISSUER + "oauth2/revoke",
    "userinfo_endpoint": ISSUER + "oauth2/userinfo",
    "account_management_uri": ISSUER + "account/",
}

pytestmark = pytest.mark.unit


def _resp(status=200, body=None):
    r = MagicMock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.json.return_value = body if body is not None else {}
    r.text = str(body)
    return r


class FakeMAS:
    """Routes requests.Session.get/post by URL and records the calls."""

    def __init__(self):
        self.posts = []
        self.token_responses = []
        self.whoami = {"user_id": "@alice:example.test", "device_id": "PHX_X"}
        self.userinfo = {"sub": "01ABC", "email": "alice@example.com"}

    def get(self, url, **kw):
        if url.endswith("/_matrix/client/v1/auth_metadata"):
            return _resp(200, META)
        if url.endswith("/account/whoami"):
            return _resp(200, self.whoami)
        if url == META["userinfo_endpoint"]:
            return _resp(200, self.userinfo)
        return _resp(404, {"error": "not found"})

    def post(self, url, json=None, data=None, **kw):
        self.posts.append((url, json or data))
        if url == META["registration_endpoint"]:
            return _resp(201, {"client_id": "CLIENT1"})
        if url == META["device_authorization_endpoint"]:
            return _resp(200, {"device_code": "DC", "user_code": "ABCDEF",
                               "verification_uri": ISSUER + "link",
                               "expires_in": 30, "interval": 0.01})
        if url == META["token_endpoint"]:
            return self.token_responses.pop(0)
        if url == META["revocation_endpoint"]:
            return _resp(200, {})
        return _resp(404, {})


@pytest.fixture()
def mas(isolated_settings, monkeypatch):
    fake = FakeMAS()
    session = MagicMock()
    session.get.side_effect = fake.get
    session.post.side_effect = fake.post
    monkeypatch.setattr(oidc, "_session", lambda: session)
    return fake


def _token_body(access="AT", refresh="RT", expires_in=300):
    return {"access_token": access, "refresh_token": refresh,
            "expires_in": expires_in, "token_type": "Bearer"}


class TestDeviceId:
    def test_format_and_stable(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(oidc, "_hardware_id", lambda: "machine-1")
        a = oidc.get_device_id()
        assert a.startswith("PHX_") and len(a) == 20
        assert a[4:].isalnum() and a[4:].isupper()
        isolated_settings.delete("oidc", "device_id")
        assert oidc.get_device_id() == a  # same hardware -> same device

    def test_hardware_id_not_sent_raw(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(oidc, "_hardware_id", lambda: "machine-1")
        assert "machine-1" not in oidc.get_device_id()

    def test_random_fallback_is_persisted(self, isolated_settings, monkeypatch):
        monkeypatch.setattr(oidc, "_hardware_id", lambda: None)
        a = oidc.get_device_id()
        assert oidc.get_device_id() == a


class TestClientRegistration:
    def test_registers_once_and_caches(self, mas):
        assert oidc.get_client_id(META) == "CLIENT1"
        assert oidc.get_client_id(META) == "CLIENT1"
        regs = [p for p in mas.posts if p[0] == META["registration_endpoint"]]
        assert len(regs) == 1
        body = regs[0][1]
        assert body["application_type"] == "native"
        assert body["token_endpoint_auth_method"] == "none"
        assert body["redirect_uris"] == ["http://127.0.0.1/callback"]

    def test_static_client_wins(self, mas, isolated_settings):
        isolated_settings.set("oidc", "static_client_id", "STATIC")
        assert oidc.get_client_id(META) == "STATIC"
        assert mas.posts == []

    def test_survives_logout(self, mas, isolated_settings):
        oidc.get_client_id(META)
        isolated_settings.clear_namespace("auth")
        oidc.get_client_id(META)
        assert len(mas.posts) == 1


class TestBrowserLogin:
    def _hit_callback(self, url, mutate=None):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        params = {"code": "CODE", "state": q["state"]}
        if mutate:
            mutate(params)
        cb = q["redirect_uri"] + "?" + urllib.parse.urlencode(params)
        threading.Thread(
            target=lambda: urllib.request.urlopen(cb, timeout=5).read(),  # nosec B310
            daemon=True).start()

    def test_full_flow(self, mas):
        mas.token_responses.append(_resp(200, _token_body()))
        seen = {}

        def opener(url):
            seen["url"] = url
            self._hit_callback(url)

        tokens = oidc.login_browser(open_url=opener)
        assert tokens.access_token == "AT" and tokens.refresh_token == "RT"
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(seen["url"]).query))
        assert q["code_challenge_method"] == "S256"
        assert q["redirect_uri"].startswith("http://127.0.0.1:")
        assert "urn:matrix:client:api:*" in q["scope"]
        assert "urn:matrix:client:device:PHX_" in q["scope"]
        form = mas.posts[-1][1]
        assert form["grant_type"] == "authorization_code"
        assert form["code"] == "CODE" and form["code_verifier"]
        assert form["redirect_uri"] == q["redirect_uri"]

    def test_state_mismatch_rejected(self, mas):
        with pytest.raises(oidc.OIDCError, match="state"):
            oidc.login_browser(open_url=lambda u: self._hit_callback(
                u, lambda p: p.update(state="evil")))

    def test_error_from_server(self, mas):
        def deny(p):
            p.pop("code")
            p.update(error="access_denied", error_description="User said no")
        with pytest.raises(oidc.OIDCError, match="User said no"):
            oidc.login_browser(open_url=lambda u: self._hit_callback(u, deny))

    def test_cancel(self, mas):
        cancel = threading.Event()
        with pytest.raises(oidc.Cancelled):
            oidc.login_browser(cancel=cancel, open_url=lambda u: cancel.set())


class TestDeviceCodeLogin:
    def test_polls_until_approved(self, mas):
        mas.token_responses += [
            _resp(400, {"error": "authorization_pending"}),
            _resp(200, _token_body(access="AT2")),
        ]
        codes = []
        tokens = oidc.login_device_code(codes.append)
        assert codes[0].user_code == "ABCDEF"
        assert tokens.access_token == "AT2"

    def test_denied(self, mas):
        mas.token_responses.append(
            _resp(400, {"error": "access_denied", "error_description": "denied"}))
        with pytest.raises(oidc.OIDCError, match="denied"):
            oidc.login_device_code(lambda dc: None)


class TestSession:
    def _login(self, mas, expires_in=300):
        oidc.complete_login(oidc.Tokens.from_response(_token_body(expires_in=expires_in)))

    def test_complete_login_stores_encrypted(self, mas, isolated_settings):
        self._login(mas)
        assert isolated_settings.get("auth", "user_id") == "@alice:example.test"
        assert isolated_settings.get("auth", "email") == "alice@example.com"
        assert isolated_settings.get("auth", "access_token").startswith("ENC:")
        assert isolated_settings.get_secret("auth", "refresh_token") == "RT"
        assert oidc.has_session()

    def test_no_email_leaves_email_unset(self, mas, isolated_settings):
        mas.userinfo = {"sub": "01ABC"}
        self._login(mas)
        assert isolated_settings.get("auth", "email") is None

    def test_refresh_not_needed(self, mas):
        self._login(mas)
        assert oidc.refresh() == "AT"
        assert not any(p[0] == META["token_endpoint"] for p in mas.posts)

    def test_refresh_when_expiring(self, mas, isolated_settings):
        self._login(mas, expires_in=10)
        mas.token_responses.append(_resp(200, {"access_token": "NEW", "expires_in": 300}))
        assert oidc.refresh() == "NEW"
        # Server did not rotate the refresh token -> the old one is kept.
        assert isolated_settings.get_secret("auth", "refresh_token") == "RT"

    def test_refresh_rejected_means_signed_out(self, mas):
        self._login(mas, expires_in=10)
        mas.token_responses.append(_resp(400, {"error": "invalid_grant"}))
        assert oidc.refresh() is None
        mas.token_responses.append(_resp(400, {"error": "invalid_grant"}))
        assert oidc.validate_session() is False

    def test_offline_keeps_session(self, mas, monkeypatch):
        self._login(mas, expires_in=10)

        def boom(*a, **k):
            raise oidc.OIDCError("offline")
        monkeypatch.setattr(oidc, "discover", boom)
        assert oidc.validate_session() is True

    def test_validate_without_session(self, isolated_settings):
        assert oidc.validate_session() is True

    def test_revoke_uses_refresh_token(self, mas):
        self._login(mas)
        oidc.revoke()
        url, form = mas.posts[-1]
        assert url == META["revocation_endpoint"]
        assert form["token"] == "RT" and form["token_type_hint"] == "refresh_token"


def test_user_agent_is_not_python_default():
    assert oidc._user_agent().startswith("Phoenix-Desktop/")


def test_tokens_expiry():
    t = oidc.Tokens.from_response({"access_token": "a", "expires_in": 60})
    assert t.expires_at and abs(t.expires_at - time.time() - 60) < 5
