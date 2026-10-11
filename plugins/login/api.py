# TODO: Remove host_url and vpn_name parameters and get them from tha API instead!!!
# TODO: Remove private_key and IP parameters and get it from the API instead!!!
# TODO: Create tests.
# TODO: Create documentation.

import json
import math
import time

import requests

from utils.logger import logger


def mask_email(email) -> str:
    """Mask an email for logs: ``john@example.com`` -> ``j***@example.com``."""
    if not isinstance(email, str) or not email:
        return "<none>"
    local, sep, domain = email.rpartition("@")
    if not sep or not local:
        return "***"
    return f"{local[0]}***@{domain}"


class LoginAPI:
    # Client-side OTP brute-force throttle: after each rejected verification
    # the next attempt is blocked for BASE * 2**(failures-1) seconds, capped.
    OTP_BACKOFF_BASE = 2.0
    OTP_BACKOFF_CAP = 64.0

    def __init__(self, base_url, clock=time.monotonic):
        self.base_url = base_url
        self._clock = clock
        self._otp_failures = 0
        self._otp_retry_at = 0.0

    def otp_retry_after(self) -> int:
        """Seconds (rounded up) until verify_otp may be called again; 0 if now."""
        remaining = self._otp_retry_at - self._clock()
        return math.ceil(remaining) if remaining > 0 else 0

    def _record_otp_failure(self):
        self._otp_failures += 1
        delay = min(
            self.OTP_BACKOFF_BASE * (2 ** (self._otp_failures - 1)),
            self.OTP_BACKOFF_CAP,
        )
        self._otp_retry_at = self._clock() + delay
        logger.info(
            f"[LOGIN] verify_otp rejected ({self._otp_failures} consecutive); "
            f"next attempt allowed in {delay:g}s"
        )

    def _reset_otp_backoff(self):
        self._otp_failures = 0
        self._otp_retry_at = 0.0

    def send_otp(self, email):
        """
        Send OTP to the specified email.
        Returns a tuple (success, message, data).
        """
        try:
            api_url = f"{self.base_url}/send-otp"
            payload = {"email": email}

            logger.info(f"[LOGIN] send_otp -> POST {api_url} | email={mask_email(email)}")
            response = requests.post(api_url, json=payload, timeout=90)
            logger.info(f"[LOGIN] send_otp <- HTTP {response.status_code}")

            if response.ok:
                try:
                    result = response.json()
                    message = result.get("message", "")
                    status = result.get("status", "").lower()
                    logger.info(f"[LOGIN] send_otp parsed: status='{status}' keys={list(result.keys())}")

                    if status in ["error", "failed", "failure", "no_subscription"]:
                        error_msg = message or result.get("error", "Failed to send OTP")
                        return False, error_msg, result
                    else:
                        success_msg = (
                            message
                            if message
                            else "OTP sent successfully! Check your email."
                        )
                        return True, success_msg, result
                except json.JSONDecodeError:
                    logger.warning(f"[LOGIN] send_otp: non-JSON response ({len(response.text or '')} bytes)")
                    return True, "OTP sent successfully! Check your email.", {}
            else:
                try:
                    error_data = response.json()
                    logger.info(f"[LOGIN] send_otp error response: HTTP {response.status_code}")
                    error_msg = error_data.get("message") or error_data.get(
                        "error", f"Server error {response.status_code}"
                    )
                except json.JSONDecodeError:
                    error_msg = f"Server error {response.status_code}"
                return False, error_msg, {}

        except requests.exceptions.RequestException as e:
            return False, f"Network error: {str(e)}", {}
        except Exception as e:
            return False, f"Error sending OTP: {str(e)}", {}

    def verify_otp(
        self,
        email: str,
        otp: str,
        public_key: str,
        hostname: str = None,
        host_url: str = "rfr1.resisti.net",
        vpn_name: str = "testVPNapi",
    ) -> tuple:
        """
        Verify the OTP and send the client public key to receive a WireGuard config.
        Returns a tuple (success, message, data).

        Rejected verifications trigger an exponential client-side backoff
        (2s, 4s, ... capped at 64s); calls made while it is active return
        ``(False, "<wait message>", {"retry_after": seconds})`` without
        contacting the server. A successful verification resets it.
        Network/transport errors do not count as failed attempts.
        """
        wait = self.otp_retry_after()
        if wait:
            logger.info(f"[LOGIN] verify_otp throttled; {wait}s remaining")
            return (
                False,
                f"Too many failed attempts. Please wait {wait}s before trying again.",
                {"retry_after": wait},
            )

        try:
            ok, message, data = self._verify_otp_request(
                email, otp, public_key, hostname, host_url, vpn_name
            )
        except requests.exceptions.RequestException as e:
            return False, f"Network error: {str(e)}", {}
        except Exception as e:
            return False, f"Verification error: {str(e)}", {}

        if ok:
            self._reset_otp_backoff()
        else:
            self._record_otp_failure()
        return ok, message, data

    def _verify_otp_request(self, email, otp, public_key, hostname, host_url, vpn_name):
        """POST /verify-otp. Transport errors propagate to verify_otp."""
        import socket

        api_url = f"{self.base_url}/verify-otp"
        payload = {
            "email": email,
            "otp": otp,
            "host_url": host_url,
            "vpn_name": vpn_name,
            "client_public_key": public_key,
            "hostname": hostname or socket.gethostname().split(".")[0],
        }

        logger.info(
            f"[LOGIN] verify_otp -> POST {api_url} | email={mask_email(email)} "
            f"| hostname={payload['hostname']}"
        )
        response = requests.post(api_url, json=payload, timeout=90)
        # Do NOT log response.text — the verify-OTP body contains the VPN
        # configuration (including the WireGuard private key).
        logger.info(f"[LOGIN] verify_otp <- HTTP {response.status_code}")

        if response.ok:
            try:
                result = response.json()
            except json.JSONDecodeError:
                logger.warning(f"[LOGIN] verify_otp: non-JSON response ({len(response.text)} bytes)")
                result = {}

            status = result.get("status", "").lower()
            message = result.get("message", "")
            logger.info(f"[LOGIN] verify_otp parsed: status='{status}' keys={list(result.keys())}")

            if (
                status == "success"
                or status == "verified"
                or "success" in message.lower()
                or "verified" in message.lower()
            ):
                return True, "OTP verified successfully!", result
            else:
                return (
                    False,
                    f"OTP verification failed: {message or 'Unknown error'}",
                    result,
                )
        else:
            try:
                error_data = response.json()
                logger.info(f"[LOGIN] verify_otp error response: HTTP {response.status_code}")
                error_msg = error_data.get("message") or error_data.get(
                    "error", f"Server error {response.status_code}"
                )
            except json.JSONDecodeError:
                error_msg = f"Server error {response.status_code}"
            return False, error_msg, {}
