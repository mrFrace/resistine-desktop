"""Chat endpoint helpers: settings resolution, TLS trust and a status probe.

The Phoenix dashboard serves a Cloudflare Origin certificate, which the
default certifi bundle does not trust. HTTPS clients for the chat endpoint
trust certifi plus that one public root (bundled in resources/certs), scoped
to these clients only.
"""

from __future__ import annotations

import os
import ssl
import time

from utils import branding, settings
from utils.functions import get_resource_path
from utils.logger import logger

TRANSPORT_OPENAI = "openai"
TRANSPORT_MATRIX = "matrix"

# Defaults older builds wrote into settings. Those hosts no longer serve chat,
# so a stored copy is treated as "use the current default".
_LEGACY_BASE_URLS = {
    "http://dashboard.resisti.net:8001/v1",
    "https://dashboard.resisti.net:8002/v1",
}
_ORIGIN_CA = os.path.join("resources", "certs", "cloudflare-origin-ca.pem")


def get_transport() -> str:
    value = settings.get("chat", "transport", TRANSPORT_OPENAI)
    return value if value in (TRANSPORT_OPENAI, TRANSPORT_MATRIX) else TRANSPORT_OPENAI


def get_assistant_mxid() -> str:
    return (settings.get("chat", "assistant_mxid")
            or branding.CHAT_DEFAULT_ASSISTANT_MXID)


def get_base_url() -> str:
    stored = settings.get("chat", "openai_base_url")
    if not stored or stored in _LEGACY_BASE_URLS:
        return branding.CHAT_DEFAULT_BASE_URL
    return stored


def tls_verify(base_url: str | None):
    """Return the ``verify`` argument for an httpx client talking to *base_url*."""
    if not base_url or not base_url.startswith("https://"):
        return True
    try:
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        ca_path = get_resource_path(_ORIGIN_CA)
        if os.path.exists(ca_path):
            ctx.load_verify_locations(ca_path)
        return ctx
    except Exception as e:
        logger.warning(f"Chat TLS: falling back to default verification: {e}")
        return True


def make_http_client(base_url: str | None, timeout: float = 600.0):
    import httpx

    return httpx.Client(verify=tls_verify(base_url), timeout=timeout)


def probe(base_url: str, api_key: str | None = None, timeout: float = 5.0) -> dict:
    """GET {base_url}/models. Blocking; call it off the Tk thread.

    Returns ``{"online", "models", "latency_ms", "error"}``.
    """
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        with make_http_client(base_url, timeout=timeout) as client:
            start = time.monotonic()
            resp = client.get(base_url.rstrip("/") + "/models", headers=headers)
            latency_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        return {"online": True, "models": len(resp.json().get("data", [])),
                "latency_ms": latency_ms, "error": None}
    except Exception as e:
        return {"online": False, "models": None, "latency_ms": None,
                "error": str(e)}
