"""utils.chat_config: the chat API base URL shared by chat, settings, dashboard."""

import pytest

from utils import chat_config


@pytest.mark.unit
class TestBaseUrl:
    def test_default_is_phoenix_host(self, isolated_settings):
        assert chat_config.base_url() == "https://dashboard.phoenix.exposed:8002/v1"

    @pytest.mark.parametrize("legacy", [
        "http://dashboard.resisti.net:8001/v1",
        "https://dashboard.resisti.net:8002/v1",
        "https://dashboard.resisti.net:8002/v1/",
    ])
    def test_saved_old_default_moves_to_new_host(self, isolated_settings, legacy):
        isolated_settings.set("chat", "openai_base_url", legacy)
        assert chat_config.base_url() == chat_config.DEFAULT_BASE_URL

    def test_custom_url_is_kept(self, isolated_settings):
        isolated_settings.set("chat", "openai_base_url", "http://localhost:11434/v1")
        assert chat_config.base_url() == "http://localhost:11434/v1"

    def test_chat_plugin_uses_shared_default(self):
        from plugins.chat import main as chat
        assert chat._DEFAULT_BASE_URL == chat_config.DEFAULT_BASE_URL
