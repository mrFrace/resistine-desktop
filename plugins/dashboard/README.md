# Dashboard Plugin

The at-a-glance view of this device: tiles the user can drag and resize.

## Tiles

- **Security posture** — this machine's grade and score from `GET /v1/me/posture`
  (`posture.py`), the score trend, the to-do items checked locally
  (`mitigations.py`; nothing is ever fixed automatically) and the other
  machines with their age when stale. "As of 7 min ago · next check 22:39".
- **Recent alerts** — opens with the week in one sentence (`weekly.py`:
  "3 alerts this week, all false positives. Nothing needs you."), then the
  newest SIEM alerts (`alerts.py`) and a seven-day strip. With the daily digest
  on (`digest.py`, Settings → Notifications) a day's quieter alerts are one
  row; high and critical stay on their own. Alert text is untrusted and is
  rendered as plain text.
- **Antivirus**, **VPN** (with the connect switch), **Endpoint**, **AI
  assistant** — each plugin's state, "Not checked" when it cannot be read.
- **System** — device facts; its header carries **Fix N things** when the
  plugins can put something right here (`utils/fixes.py`), which opens the
  Fixes page: one row per fix, run all or one at a time, each as a job with a
  code. Only fixes about this machine are offered.

## Behaviour

- Data is gathered off the UI thread every 20 s and cached on the plugin, so
  a rebuild paints at once.
- The sidebar logo's glow is the Endpoint agent's state.
- Once a week the sentence is posted into the user's SIEM alerts DM over the
  running Matrix session (counts and tile names only).
- The sentence says "Nothing needs you." only when nothing is unread or
  confirmed, nothing is left to fix here and no tile is in error or unknown.
