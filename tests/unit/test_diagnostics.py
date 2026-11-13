"""Diagnostics report and its redaction (utils/diagnostics.py)."""

import os

import pytest

from plugins.base_plugin import Status
from utils import diagnostics, jobs, settings

pytestmark = pytest.mark.unit

WG_KEY = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9.eyJzdWIiOiJAZnJhbmNpczpwaG9lbml4LmV4cG9zZWQifQ.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
RECOVERY = "EsTx Abcd Efgh Ijkl Mnop Qrst Uvwx Yzab Cdef Ghij Klmn Opqr"


@pytest.mark.parametrize("line,expected", [
    (f"PrivateKey = {WG_KEY}", "PrivateKey = [redacted]"),
    (f"[Peer] PresharedKey={WG_KEY}", "[Peer] PresharedKey = [redacted]"),
    (f"peer public key {WG_KEY} added", "peer public key [key] added"),
    (f"recovery key: {RECOVERY}", "recovery key = [redacted]"),
    (f"typed {RECOVERY} into the field", "typed [recovery key] into the field"),
    ("Authorization: Bearer mat_abcdefghijklmnop", "Authorization = [redacted]"),
    ("sent bearer mat_abcdefghijklmnop ok", "sent Bearer [redacted] ok"),
    (f"token={JWT}", "token = [redacted]"),
    (f"got {JWT} back", "got [blob] back"),
    ('{"api_key": "sk-123456", "password": "hunter2"}', '{"api_key = [redacted]'),
    ("WireGuard PrivateKey=abc, then more text", "WireGuard PrivateKey = [redacted]"),
    ("value ENC:gAAAAABl... stored", "value ENC:[redacted] stored"),
    ("agent 017 drake-laptop any " + "A" * 64, "agent 017 drake-laptop any [blob]"),
    ("?code=abcdef123456&state=xyz12345", "?code=abcd…&state=xyz1…"),
    ("plain line, user @francis:phoenix.exposed, 10.42.20.14", "plain line, user @francis:phoenix.exposed, 10.42.20.14"),
    ("bidi ‮ tricks\x1b[0m", "bidi  tricks[0m"),
])
def test_redact(line, expected):
    assert diagnostics.redact(line) == expected


def test_redact_keeps_lines_and_caps_them():
    text = "a\n" + "b " * 500 + "\nc"
    out = diagnostics.redact(text).splitlines()
    assert out[0] == "a" and out[2] == "c" and len(out[1]) == diagnostics._MAX_LINE


def test_services_skip_off_plugins():
    rows = diagnostics.services({"VPN": Status("off"), "Endpoint": Status("unknown", "Not checked"),
                                 "Antivirus": Status("ok")})
    assert rows == [("Endpoint", "unknown", "Not checked"), ("Antivirus", "ok", "")]
    assert diagnostics.services(None) == []


def test_report_has_every_part_and_is_redacted(isolated_settings, monkeypatch):
    jobs._reset_for_tests()
    settings.set("auth", "user_id", "@francis:phoenix.exposed")
    job = jobs.start("vpn", "VPN connect", "drake-laptop")
    jobs.finish(job["code"], ok=False, summary=f"PrivateKey = {WG_KEY}")
    log_dir = os.path.join(settings.get_config_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "phoenix.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(f"line {i}" for i in range(200)) + f"\nlast token=mat_secretsecret {WG_KEY}\n")
    text = diagnostics.report({"VPN": Status("ok", "Connected")})
    assert text.startswith("Phoenix Desktop diagnostics")
    assert "Account: @francis:phoenix.exposed" in text
    assert "  VPN: ok — Connected" in text
    assert f"  {job['code']}  VPN connect (drake-laptop) · failed just now · PrivateKey = [redacted]" in text
    assert "Log (last 80 lines of phoenix.log)" in text
    assert "line 199" in text and "line 100" not in text
    assert "last token = [redacted]" in text
    assert WG_KEY not in text and "mat_secretsecret" not in text
    assert diagnostics.log_tail() and diagnostics.events()[0][0] == job["code"]
    jobs._reset_for_tests()


def test_missing_log_is_fine(isolated_settings):
    jobs._reset_for_tests()
    assert diagnostics.log_tail() == []
    assert "Log (" not in diagnostics.report()
