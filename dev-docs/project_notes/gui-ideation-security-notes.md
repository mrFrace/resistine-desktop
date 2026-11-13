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

Built 2026-11-13: `utils/fixes.py`. "Fix all" is a queue of the plugins'
own actions (`BasePlugin.fixes()` / `run_fix(id)`, a closed set of ids,
no arguments): start or re-enrol the Endpoint agent, update antivirus
signatures, connect the VPN, remove this machine's earlier installs.
Installing the agent and setting up the antivirus are not in it (both
happen at sign-in). `gate()` drops any fix whose host is not this
machine; the fleet view never runs a repair on another device. One job
per fix; a failure skips only what depended on it; admin prompts happen
inside each fix's own function and the page says how many to expect.
A VPN switched off by hand is remembered (`vpn.user_disconnected`) and
not offered as a fix until the user switches it on again.

## "Copy diagnostics" / recent-events timeline

A clipboard export of log tail, versions, service states and recent
failures must go through the same redaction as `utils/http_trace.py`
(`_SECRET_KEYS`: tokens, ciphertext, keys, passwords) and must never
include the recovery key, the WireGuard private key or the agent key. The
timeline shown in the app is fine; the export is the risk.

Built 2026-11-13: Settings → Diagnostics (`utils/diagnostics.py`). The
report goes through `redact()`: the http_trace masks plus "PrivateKey =",
bearer, `ENC:` values, WireGuard-key, recovery-key and long-blob shapes.
Nothing is read from the secret store.

## Job tracking codes shown in Chat

If every fix/scan/install gets a short code the user can ask the AI
assistant about, the assistant needs read access to job state. That is
local data only; do not send job details to the chat endpoint unless the
user asked about that code, and treat the returned text like any other
untrusted content (`markdown_to_html(..., allow_html=False)`, links off).

Built 2026-11-13: `utils/jobs.py` (codes `PX-4K7Q`, local `jobs.json`,
0600). The chat attaches a job's details only when its code is in the
question, and marks that answer's bubble untrusted.

## Batching or delaying SIEM alerts ("hold mail", daily digest)

Alert batching must bypass for high severity: a critical alert is shown
immediately whatever the digest setting. The batching happens in the
view, never by acknowledging alerts on the server. Alert text stays
untrusted when quoted in a digest line.

Built 2026-11-13: `plugins/dashboard/digest.py`, Settings → Notifications
→ Daily alert digest. Critical and high always on their own row; the
store is untouched; digest lines carry counts and host names only.

## Undo / "returns desk" for applied fixes

A revert of a system change (VPN config, agent reinstall, ClamAV units)
cannot be promised in general. If offered, each fix declares whether it
is reversible and how; the undo runs the same privileged, allowlisted
path as the fix, with the same validation of what is being restored.

Built 2026-11-13: a job declares its undo when it starts (`utils/jobs.py`
`undo={label, plugin, action, arg}`); `BasePlugin.undo(action, arg)` keeps
a closed set per plugin and re-validates the argument. VPN connect ↔
disconnect through `request_toggle`; agent install → `remove_agent()`,
the reinstall path's own function, never the identity wipe. A scan and
an update check declare nothing. Only the newest done job of a kind can
be undone; the Diagnostics row confirms in place, no dialog.
