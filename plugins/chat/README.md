# AI Security Assistant (Chat Plugin)

The Chat plugin transforms the Phoenix XDR system into an intelligent, conversational security platform. It acts as your **AI Security Assistant**, helping you navigate complex security data and manage your infrastructure through natural language.

## Empowering Your Security Workflow

The Chat plugin is designed to help you achieve critical security objectives with ease:

- **Instant Agent Insights**: Get real-time status updates on your monitored assets. Ask things like _"Which agents are currently active?"_ or _"Summarize the status of Agent 008."_
- **Proactive Vulnerability Analysis**: Quickly identify risks across your systems. Use the AI to discover outdated packages or high-priority CVEs without digging through raw logs.
- **Compliance & Hardening Audits**: Leverage AI to interpret Security Configuration Assessment (SCA) and CIS-CAT benchmark results, making hardening recommendations easy to understand and act upon.
- **Interactive Security Expertise**: Get context-aware help with network configurations, open ports, and system processes.

## A Premium Conversational Experience

To support high-stakes security analysis, the plugin features a state-of-the-art UI:

- **Rich Security Reporting**: High-fidelity Markdown rendering for vulnerability tables, security scan results, and formatted code snippets.
- **Live Response Streaming**: Real-time token delivery ensures you get security answers the moment they are generated.
- **Responsive Adaptive Interface**: Optimally constrained bubbles and dynamic reflow for a professional, readable chat experience that adapts to any window size.
- **Seamless Continuity**: Your security context and conversation history are preserved even as you switch between different Phoenix plugins.

## Technical Architecture

- **MarkdownBubble Engine**: A specialized rendering component for compliant HTML/CSS display of security data.
- **Decoupled Modular Styling**: Dedicated chat stylesheets ensure visual isolation and consistent performance.
- **Hybrid API Support**: Optimized for both standard OpenAI and stateful custom Phoenix API endpoints.

## Getting Started

Visit the **Settings** plugin to bridge your AI assistant to your preferred backend:

- Configure **OpenAI** or **Custom Phoenix API** endpoints.
- Select your preferred **Inference Model**.
- Define the **Security System Prompt**.
- Toggle UI preferences like **Typing Animations**.
