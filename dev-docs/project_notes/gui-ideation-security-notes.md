# Security notes from the GUI ideation (2026-11-12)

Side notes from an /adhd ideation run on the GUI. The run was about design
and functionality only; these are the places where an idea touches
security and must be decided before the idea is built. Not a plan.

## Chained fixes ("Make it all green", "Fix all")

Running every safe fix in one sweep means several privileged commands
(root `sh -c`, `osascript ... with administrator privileges`, elevated
PowerShell) back to back. Keep each fix going through its own existing,
allowlisted path; the sweep must not build one combined command string.
One admin prompt per sweep is fine only where the platform's elevation
helper already supports it. A fix that needs settings- or server-supplied
values keeps the per-value sanitisation (CLAUDE.md, security conventions).

## "Copy diagnostics" / recent-events timeline

A clipboard export of log tail, versions, service states and recent
failures must go through the same redaction as `utils/http_trace.py`
(`_SECRET_KEYS`: tokens, ciphertext, keys, passwords) and must never
include the recovery key, the WireGuard private key or the agent key. The
timeline shown in the app is fine; the export is the risk.

## Job tracking codes shown in Chat

If every fix/scan/install gets a short code the user can ask the AI
assistant about, the assistant needs read access to job state. That is
local data only; do not send job details to the chat endpoint unless the
user asked about that code, and treat the returned text like any other
untrusted content (`markdown_to_html(..., allow_html=False)`, links off).

## Batching or delaying SIEM alerts ("hold mail", daily digest)

Alert batching must bypass for high severity: a critical alert is shown
immediately whatever the digest setting. The batching happens in the
view, never by acknowledging alerts on the server. Alert text stays
untrusted when quoted in a digest line.

## Undo / "returns desk" for applied fixes

A revert of a system change (VPN config, agent reinstall, ClamAV units)
cannot be promised in general. If offered, each fix declares whether it
is reversible and how; the undo runs the same privileged, allowlisted
path as the fix, with the same validation of what is being restored.
