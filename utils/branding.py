"""User-facing product branding.

Only names and links a user sees live here. Internal identifiers keep the
legacy "Resistine" spelling on purpose — config dirs, keyring service names,
bundle ids, service names and install paths are part of existing installs,
and renaming them would orphan settings and make stored secrets unreadable.
"""

APP_NAME = "Phoenix"
APP_TAGLINE = "Phoenix Security Desktop"
AI_NAME = "Phoenix AI"

WEBSITE_URL = "https://phoenix.exposed"
ACCOUNT_URL = "https://auth.phoenix.exposed/account/"

# Chat (OpenAI-compatible) endpoint served by Phoenix-LLMAgent-api.
CHAT_DEFAULT_BASE_URL = "https://dashboard.phoenix.exposed:8002/v1"
# Matrix account the desktop chats with when the Matrix transport is selected.
CHAT_DEFAULT_ASSISTANT_MXID = "@secagent:phoenix.exposed"

LOGO_MARK = "PhoenixMark.png"
