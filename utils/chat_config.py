"""Where the chat plugin's OpenAI-compatible API lives.

Shared by the chat, settings and dashboard plugins so they agree on the
default and on how a saved value is read.
"""

from utils import settings

DEFAULT_BASE_URL = "https://dashboard.phoenix.exposed:8002/v1"

# Defaults older builds saved into settings. Those hosts no longer serve the
# chat API, so a stored copy means "use the current default".
_LEGACY_BASE_URLS = {
    "http://dashboard.resisti.net:8001/v1",
    "https://dashboard.resisti.net:8002/v1",
}


def base_url() -> str:
    """The configured chat API base URL, or the default."""
    stored = settings.get("chat", "openai_base_url")
    if not stored or stored.rstrip("/") in _LEGACY_BASE_URLS:
        return DEFAULT_BASE_URL
    return stored
