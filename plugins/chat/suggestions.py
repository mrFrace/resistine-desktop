"""Suggestion prompts for the chat welcome screen (framework-free).

Each prompt maps to a tool the Phoenix AI server (LLMAgent-api) exposes, so
a click returns live data from the user's own agents instead of a generic
lecture. Admin-only tools (pentest, active response) and ones Wazuh 5
cannot serve (agent config, CIS-CAT) are left out on purpose.
"""

import random

# Grouped by area; the welcome screen shows one prompt from each of 4
# different groups so a new chat always offers a spread of capabilities.
SUGGESTION_GROUPS: dict[str, list[str]] = {
    "agents": [
        "List all my monitored devices and their status",          # get_user_agents
        "Give me a summary of my fleet: how many agents are active?",  # get_agents_summary
        "Which agent owns the IP address of this device?",          # get_agent_by_ip
        "Show the hardware details of this device",                 # get_agent_hardware
        "Which operating system and kernel is each agent running?",  # get_agent_os
    ],
    "inventory": [
        "Show the open network ports on this device",               # get_agent_ports
        "What processes are running on this device right now?",     # get_agent_processes
        "List the software packages installed on this device",       # get_agent_packages
        "Show the network interfaces and IP addresses of this device",  # get_agent_network
        "Analyze the inventory of this device for anything unusual",  # run_inventory_analysis
    ],
    "posture": [
        "Give me a quick security status of my devices",            # get_security_status
        "Calculate the risk score for this device",                 # calculate_risk_score
        "Run a security diagnostic on this device",                 # run_security_diagnostic
        "Show the file integrity monitoring results for this device",  # get_agent_security_scans
    ],
    "vulnerabilities": [
        "Which critical vulnerabilities affect my devices?",         # get_vulnerability_overview
        "List the vulnerabilities on this device, worst first",     # get_agent_vulnerabilities
        "How do I fix the most severe vulnerability on this device?",  # get_remediation
        "Search my devices for high-severity CVEs from this year",   # search_vulnerabilities_direct
    ],
    "compliance": [
        "Assess this device against the CIS benchmark",             # assess_compliance
        "Which configuration checks failed on this device, and how do I fix them?",  # get_failed_sca_checks
        "How compliant are my devices with ISO 27001?",              # assess_compliance
        "Show the SCA policy results for this device",              # get_agent_sca
    ],
    "alerts": [
        "Show my most recent security alerts",                      # get_recent_alerts
        "Which of my recent alerts are actually important?",         # select_important_alerts
        "Hunt for hidden threats across my devices",                # hunt_for_threats
        "Detect any unusual behaviour on my devices this week",      # detect_anomalies
        "Correlate today's alerts: is anything connected?",          # correlate_events
    ],
    "intel": [
        "Is the IP address 185.220.101.1 known to be malicious?",    # enrich_indicator
        "Explain MITRE ATT&CK technique T1059 and how to mitigate it",  # get_mitre_data
        "Explain CVE-2024-3094 and whether it affects me",           # get_cve_details
        "Create an incident response playbook for a ransomware infection",  # create_incident_playbook
    ],
    "reports": [
        "Generate a security report of my devices for management",  # generate_report
        "Write a Wazuh rule for this log line: sshd[123]: Failed password for root from 10.0.0.5",  # create_rule_decoder
        "What version is the Wazuh manager running?",               # get_manager_info
        "What is the status of my background security jobs?",       # get_tasks_status
    ],
}

# Flat view, kept for callers that want the whole pool.
SUGGESTION_POOL: list[str] = [
    s for group in SUGGESTION_GROUPS.values() for s in group]


def pick_suggestions(count: int = 4, rng: random.Random | None = None) -> list[str]:
    """``count`` prompts, each from a different group (random groups)."""
    rng = rng or random.Random()
    groups = rng.sample(list(SUGGESTION_GROUPS),
                        min(count, len(SUGGESTION_GROUPS)))
    return [rng.choice(SUGGESTION_GROUPS[g]) for g in groups]
