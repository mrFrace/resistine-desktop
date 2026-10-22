"""
Unit tests for plugins/wazuh/agent/agent_state.py.

The agent's real manager-connection status comes from Wazuh's own
wazuh-agentd.state file (with an ossec.log fallback). Reading it is what lets
the UI tell "running" apart from "running but never connected" — the state a
reinstalled agent lands in when the operator deletes the old agent
server-side, invalidating the reused key. These tests pin the parsing so that
signal stays trustworthy (the auto-detect + Reconnect flow depends on it).
"""

import pytest

from plugins.wazuh.agent import agent_state


@pytest.mark.unit
class TestParseAgentdState:
    def test_connected(self):
        text = "# state\nstatus='connected'\nlast_ack='2026-06-30 22:00:00'\n"
        assert agent_state.parse_agentd_state(text) == agent_state.CONNECTED

    def test_pending(self):
        assert agent_state.parse_agentd_state("status='pending'") == agent_state.PENDING

    def test_disconnected(self):
        assert (
            agent_state.parse_agentd_state("status='disconnected'")
            == agent_state.DISCONNECTED
        )

    def test_double_quoted_and_whitespace(self):
        assert (
            agent_state.parse_agentd_state('  status =  "connected"  ')
            == agent_state.CONNECTED
        )

    def test_comments_and_blank_lines_ignored(self):
        text = "\n# status='disconnected' (this is a comment)\n\nstatus='connected'\n"
        assert agent_state.parse_agentd_state(text) == agent_state.CONNECTED

    def test_unknown_when_absent(self):
        assert (
            agent_state.parse_agentd_state("msg_count='5'\nlast_ack=''")
            == agent_state.UNKNOWN
        )

    def test_unrecognized_value_is_unknown(self):
        assert agent_state.parse_agentd_state("status='banana'") == agent_state.UNKNOWN


@pytest.mark.unit
class TestParseOssecLogTail:
    def test_last_signal_wins_connected(self):
        text = (
            "Unable to connect to any configured manager\n"
            "INFO: Connected to the server (dashboard:1514)\n"
        )
        assert agent_state.parse_ossec_log_tail(text) == agent_state.CONNECTED

    def test_last_signal_wins_disconnected(self):
        text = (
            "INFO: Connected to the server\n"
            "ERROR: Lost connection with manager. Setting lock.\n"
        )
        assert agent_state.parse_ossec_log_tail(text) == agent_state.DISCONNECTED

    def test_unknown_when_no_signal(self):
        assert agent_state.parse_ossec_log_tail("just some log noise\n") == agent_state.UNKNOWN


@pytest.mark.unit
class TestReadAgentConnection:
    def test_prefers_state_file(self, tmp_path):
        state = tmp_path / "wazuh-agentd.state"
        state.write_text("status='connected'\n")
        assert (
            agent_state.read_agent_connection(str(state), None)
            == agent_state.CONNECTED
        )

    def test_falls_back_to_log_when_state_missing(self, tmp_path):
        log = tmp_path / "ossec.log"
        log.write_text("INFO: Connected to the server\n")
        missing_state = str(tmp_path / "nope.state")
        assert (
            agent_state.read_agent_connection(missing_state, str(log))
            == agent_state.CONNECTED
        )

    def test_falls_back_to_log_when_state_unparseable(self, tmp_path):
        state = tmp_path / "wazuh-agentd.state"
        state.write_text("garbage without a status line\n")
        log = tmp_path / "ossec.log"
        log.write_text("ERROR: Unable to connect to any configured manager\n")
        assert (
            agent_state.read_agent_connection(str(state), str(log))
            == agent_state.DISCONNECTED
        )

    def test_unknown_when_nothing_readable(self, tmp_path):
        assert (
            agent_state.read_agent_connection(
                str(tmp_path / "a.state"), str(tmp_path / "b.log")
            )
            == agent_state.UNKNOWN
        )

    def test_never_raises_on_missing_paths(self):
        # Must degrade to "unknown", not raise — it runs on every status poll.
        assert (
            agent_state.read_agent_connection("/no/such/state", "/no/such/log")
            == agent_state.UNKNOWN
        )
