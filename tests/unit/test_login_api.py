"""
Comprehensive unit tests for LoginAPI.

Covers:
- OTP send success / failure / edge cases
- OTP verify success / failure / edge cases
- Network / timeout errors
- Payload structure validation
- Response parsing edge cases (non-JSON, empty body)
- Status string variations ("success", "verified", "failed", etc.)
"""
import json
import pytest
import requests
from unittest.mock import MagicMock, patch, call

from plugins.login.api import LoginAPI

BASE_URL = "https://test.resistine.work"


@pytest.fixture()
def api():
    return LoginAPI(BASE_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mock_response(ok=True, status_code=200, body=None, raise_json=False):
    resp = MagicMock()
    resp.ok = ok
    resp.status_code = status_code
    if raise_json:
        resp.json.side_effect = json.JSONDecodeError("bad json", "", 0)
        resp.text = body or ""
    else:
        resp.json.return_value = body or {}
        resp.text = json.dumps(body or {})
    return resp


# ===========================================================================
# send_otp
# ===========================================================================
class TestSendOTP:
    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_success_returns_true_with_message(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success", "message": "OTP sent"})
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is True
        assert "OTP sent" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_success_no_message_uses_default(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is True
        assert "email" in msg.lower()  # "Check your email"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_status_error_returns_false(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "error", "message": "Invalid email"})
        ok, msg, data = api.send_otp("bad")
        assert ok is False
        assert "Invalid email" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_status_failed_returns_false(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "failed", "message": "Not registered"})
        ok, msg, data = api.send_otp("unknown@example.com")
        assert ok is False

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_status_no_subscription_returns_false(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "no_subscription", "message": "Subscribe first"})
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "Subscribe first" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_http_error_returns_false(self, mock_post, api):
        mock_post.return_value = _mock_response(ok=False, status_code=500, body={"message": "Internal error"})
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "Internal error" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_http_error_non_json_body(self, mock_post, api):
        mock_post.return_value = _mock_response(ok=False, status_code=503, raise_json=True, body="Service Unavailable")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "503" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_non_json_success_response(self, mock_post, api):
        """200 OK but non-JSON body — treated as success."""
        mock_post.return_value = _mock_response(ok=True, status_code=200, raise_json=True, body="OK")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is True
        assert data == {}

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_network_error(self, mock_post, api):
        mock_post.side_effect = requests.exceptions.RequestException("Connection refused")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "Network error" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_timeout_error(self, mock_post, api):
        mock_post.side_effect = requests.exceptions.Timeout("timed out")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "Network error" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_sends_correct_url(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.send_otp("user@example.com")
        call_args = mock_post.call_args
        assert call_args[0][0] == f"{BASE_URL}/send-otp"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_sends_email_in_payload(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.send_otp("myuser@acme.com")
        payload = mock_post.call_args[1]["json"]
        assert payload["email"] == "myuser@acme.com"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_uses_90s_timeout(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.send_otp("user@example.com")
        assert mock_post.call_args[1]["timeout"] == 90

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_returns_response_data(self, mock_post, api):
        body = {"status": "success", "message": "OTP sent", "extra_field": "value"}
        mock_post.return_value = _mock_response(body=body)
        ok, msg, data = api.send_otp("user@example.com")
        assert data == body

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_unexpected_exception_handled(self, mock_post, api):
        mock_post.side_effect = RuntimeError("unexpected")
        ok, msg, data = api.send_otp("user@example.com")
        assert ok is False
        assert "Error sending OTP" in msg


# ===========================================================================
# verify_otp
# ===========================================================================
class TestVerifyOTP:
    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_success_status(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success", "message": "Verified"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is True
        assert "verified successfully" in msg.lower()

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_verified_status(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "verified", "message": "All good"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is True

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_success_in_message_text(self, mock_post, api):
        """Even if status is unknown, 'success' in the message body should pass."""
        mock_post.return_value = _mock_response(body={"status": "ok", "message": "Authentication success"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is True

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_verified_in_message_text(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "ok", "message": "Account verified"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is True

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_failed_otp(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "failed", "message": "Wrong OTP"})
        ok, msg, data = api.verify_otp("u@e.com", "000000", "pubkey==")
        assert ok is False
        assert "OTP verification failed" in msg
        assert "Wrong OTP" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_expired_otp(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "error", "message": "OTP expired"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is False

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_http_error(self, mock_post, api):
        mock_post.return_value = _mock_response(ok=False, status_code=401, body={"message": "Unauthorized"})
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is False
        assert "Unauthorized" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_http_error_non_json(self, mock_post, api):
        mock_post.return_value = _mock_response(ok=False, status_code=502, raise_json=True)
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is False
        assert "502" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_non_json_success_response(self, mock_post, api):
        """200 with non-JSON body → empty result dict, but NOT treated as success."""
        mock_post.return_value = _mock_response(ok=True, raise_json=True, body="")
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        # status="" so success/verified not in status or message → should fail
        assert ok is False

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_network_error(self, mock_post, api):
        mock_post.side_effect = requests.exceptions.ConnectionError("no route")
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is False
        assert "Network error" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_sends_correct_url(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "pubkey==")
        assert mock_post.call_args[0][0] == f"{BASE_URL}/verify-otp"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_payload_contains_all_required_fields(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "pubkey==")
        payload = mock_post.call_args[1]["json"]
        for field in ("email", "otp", "client_public_key", "hostname", "host_url", "vpn_name"):
            assert field in payload, f"Missing field: {field}"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_default_hostname_is_non_empty(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "pubkey==")
        payload = mock_post.call_args[1]["json"]
        assert isinstance(payload["hostname"], str)
        assert len(payload["hostname"]) > 0

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_custom_hostname_used(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "pubkey==", hostname="my-test-box")
        payload = mock_post.call_args[1]["json"]
        assert payload["hostname"] == "my-test-box"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_public_key_sent_in_payload(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "MY_PUBLIC_KEY==")
        payload = mock_post.call_args[1]["json"]
        assert payload["client_public_key"] == "MY_PUBLIC_KEY=="

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_otp_sent_in_payload(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "654321", "pubkey==")
        payload = mock_post.call_args[1]["json"]
        assert payload["otp"] == "654321"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_vpn_config_returned_on_success(self, mock_post, api):
        body = {"status": "success", "vpn_config": '{"Interface": {}, "Peer": {}}'}
        mock_post.return_value = _mock_response(body=body)
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is True
        assert "vpn_config" in data

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_unexpected_exception_handled(self, mock_post, api):
        mock_post.side_effect = RuntimeError("crash")
        ok, msg, data = api.verify_otp("u@e.com", "123456", "pubkey==")
        assert ok is False
        assert "Verification error" in msg

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_uses_90s_timeout(self, mock_post, api):
        mock_post.return_value = _mock_response(body={"status": "success"})
        api.verify_otp("u@e.com", "123456", "pubkey==")
        assert mock_post.call_args[1]["timeout"] == 90


# ===========================================================================
# LoginAPI initialization
# ===========================================================================
class TestLoginAPIInit:
    @pytest.mark.unit
    def test_base_url_stored(self):
        api = LoginAPI("https://custom.backend.io")
        assert api.base_url == "https://custom.backend.io"

    @pytest.mark.unit
    def test_base_url_trailing_slash_preserved(self):
        """LoginAPI must not silently strip trailing slashes — URL concatenation relies on exact value."""
        api = LoginAPI("https://backend.io/")
        assert api.base_url == "https://backend.io/"


# ===========================================================================
# Log redaction (email masked, response bodies never logged)
# ===========================================================================
@pytest.fixture()
def captured_logs():
    from utils.logger import logger

    lines = []
    sink_id = logger.add(lambda m: lines.append(str(m)), level="DEBUG")
    yield lines
    logger.remove(sink_id)


class TestMaskEmail:
    @pytest.mark.unit
    @pytest.mark.parametrize(
        "email,expected",
        [
            ("john@example.com", "j***@example.com"),
            ("a@b.io", "a***@b.io"),
            ("no-at-sign", "***"),
            ("@example.com", "***"),
            ("", "<none>"),
            (None, "<none>"),
        ],
    )
    def test_mask(self, email, expected):
        from plugins.login.api import mask_email

        assert mask_email(email) == expected


class TestLogRedaction:
    SECRET = "SUPERSECRETTOKEN"

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_send_otp_masks_email_and_omits_body(self, mock_post, api, captured_logs):
        mock_post.return_value = _mock_response(
            body={"status": "success", "message": f"sent to john.doe@acme.com {self.SECRET}"}
        )
        api.send_otp("john.doe@acme.com")
        logs = "\n".join(captured_logs)
        assert "john.doe@acme.com" not in logs
        assert "j***@acme.com" in logs
        assert "HTTP 200" in logs
        assert self.SECRET not in logs

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_send_otp_non_json_body_not_logged(self, mock_post, api, captured_logs):
        mock_post.return_value = _mock_response(body=f"<html>{self.SECRET}</html>", raise_json=True)
        api.send_otp("john.doe@acme.com")
        assert self.SECRET not in "\n".join(captured_logs)

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_send_otp_error_body_not_logged(self, mock_post, api, captured_logs):
        mock_post.return_value = _mock_response(
            ok=False, status_code=400, body={"message": "bad", "detail": self.SECRET}
        )
        api.send_otp("john.doe@acme.com")
        logs = "\n".join(captured_logs)
        assert self.SECRET not in logs
        assert "HTTP 400" in logs

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_verify_otp_masks_email_and_omits_body(self, mock_post, api, captured_logs):
        mock_post.return_value = _mock_response(
            body={"status": "success", "message": "verified", "vpn_config": {"PrivateKey": self.SECRET}}
        )
        api.verify_otp("john.doe@acme.com", "123456", "pubkey==")
        logs = "\n".join(captured_logs)
        assert "john.doe@acme.com" not in logs
        assert "j***@acme.com" in logs
        assert self.SECRET not in logs
        assert "123456" not in logs

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_verify_otp_error_body_not_logged(self, mock_post, api, captured_logs):
        mock_post.return_value = _mock_response(
            ok=False, status_code=401, body={"message": "nope", "token": self.SECRET}
        )
        api.verify_otp("john.doe@acme.com", "123456", "pubkey==")
        logs = "\n".join(captured_logs)
        assert self.SECRET not in logs
        assert "HTTP 401" in logs


# ===========================================================================
# OTP verification backoff (2s base, doubling, 64s cap; reset on success)
# ===========================================================================
class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture()
def clocked_api():
    clock = _Clock()
    return LoginAPI(BASE_URL, clock=clock), clock


def _fail():
    return _mock_response(body={"status": "failed", "message": "Invalid OTP"})


def _ok():
    return _mock_response(body={"status": "success"})


class TestOtpBackoff:
    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_first_attempt_not_throttled(self, mock_post, clocked_api):
        api, _ = clocked_api
        mock_post.return_value = _ok()
        ok, _, _ = api.verify_otp("u@e.com", "123456", "pk")
        assert ok
        assert api.otp_retry_after() == 0

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_failure_blocks_next_attempt_without_network(self, mock_post, clocked_api):
        api, clock = clocked_api
        mock_post.return_value = _fail()
        api.verify_otp("u@e.com", "000000", "pk")
        assert mock_post.call_count == 1

        clock.t += 1
        ok, msg, data = api.verify_otp("u@e.com", "000001", "pk")
        assert not ok
        assert mock_post.call_count == 1  # server not contacted
        assert "wait 1s" in msg
        assert data == {"retry_after": 1}

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_delay_doubles_and_caps_at_64(self, mock_post, clocked_api):
        api, clock = clocked_api
        mock_post.return_value = _fail()
        delays = []
        for _ in range(8):
            api.verify_otp("u@e.com", "000000", "pk")
            delays.append(api.otp_retry_after())
            clock.t += delays[-1]  # wait out the backoff
        assert delays == [2, 4, 8, 16, 32, 64, 64, 64]

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_allowed_after_wait(self, mock_post, clocked_api):
        api, clock = clocked_api
        mock_post.return_value = _fail()
        api.verify_otp("u@e.com", "000000", "pk")
        clock.t += 2
        mock_post.return_value = _ok()
        ok, _, _ = api.verify_otp("u@e.com", "123456", "pk")
        assert ok
        assert mock_post.call_count == 2

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_success_resets_backoff(self, mock_post, clocked_api):
        api, clock = clocked_api
        mock_post.return_value = _fail()
        api.verify_otp("u@e.com", "0", "pk")
        clock.t += 2
        api.verify_otp("u@e.com", "0", "pk")
        clock.t += 4
        mock_post.return_value = _ok()
        assert api.verify_otp("u@e.com", "1", "pk")[0]
        mock_post.return_value = _fail()
        api.verify_otp("u@e.com", "0", "pk")
        assert api.otp_retry_after() == 2  # back to the base delay

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_http_error_counts_as_failure(self, mock_post, clocked_api):
        api, _ = clocked_api
        mock_post.return_value = _mock_response(ok=False, status_code=401, body={"message": "bad otp"})
        api.verify_otp("u@e.com", "0", "pk")
        assert api.otp_retry_after() == 2

    @pytest.mark.unit
    @patch("plugins.login.api.requests.post")
    def test_network_error_does_not_trigger_backoff(self, mock_post, clocked_api):
        api, _ = clocked_api
        mock_post.side_effect = requests.exceptions.ConnectionError("down")
        ok, msg, data = api.verify_otp("u@e.com", "0", "pk")
        assert not ok and "Network error" in msg and data == {}
        assert api.otp_retry_after() == 0
