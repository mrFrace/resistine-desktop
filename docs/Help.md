# Phoenix Help

Welcome to **Phoenix** — AI EndPoint Detection and Response (AI EDR) for
Windows, macOS, and Linux. This page is your starting point; use the dropdown
above to browse the other help topics.

## Getting Started

Sign in from the **Login** screen, then use the sidebar on the left to move
between features. The **Dashboard** gives you a one-glance view of your
protection status — start there.

## Features

Each item in the sidebar is a feature:

- **Dashboard** — Your week in one sentence, the security posture of your
  machines, recent alerts and each feature's state. When Phoenix can put
  something right on this computer, the System tile shows **Fix N things**:
  each fix is one of the features' own actions, run one at a time, and the
  page tells you how many password prompts to expect. Phoenix never updates
  packages or restarts your computer for you.
- **Alerts** — Security alerts about your machines from the Phoenix SIEM.
  Turn on **Daily alert digest** in Settings to see a day's quieter alerts as
  one row; high and critical alerts always appear on their own.
- **Chat** — Ask the Phoenix AI assistant for help and guidance. Type a job
  code (for example `PX-4K7Q`, from Settings → Diagnostics) to ask about
  something Phoenix did on this computer.
- **VPN** — Connect to a secure WireGuard VPN and manage your configurations.
- **Endpoint** — Install and manage the SIEM agent that monitors your device.
- **Devices** — Every machine on your account, their posture, and the
  sessions signed in to it.
- **Antivirus** — Scan, quarantine, and protect against malware.
- **Store** — Browse and install additional plugins.
- **Help** — This documentation.
- **Settings** — Your account, the AI assistant, appearance, notifications,
  updates and **Diagnostics**.

Chat needs the Endpoint agent running. If a feature seems unavailable, check
the Endpoint screen first.

An amber glow on a feature's icon means Phoenix could not check it: the
caption under the icon says why. If it stays that way, a message offers
**Check now**.

## Troubleshooting

- **A feature won't load** — Make sure you're signed in and, where required,
  connected to the VPN. Restarting the app clears most transient issues.
- **VPN won't connect** — Check your internet connection and confirm your
  configuration under the VPN tab.
- **Something looks wrong** — Settings → **Check for updates** fetches the
  current release; see **Releases** (in the dropdown above) for details.
- **Asking for help** — Settings → Diagnostics → **Copy diagnostics** puts
  versions, states, recent jobs and the end of the log on the clipboard, with
  keys, tokens and passwords removed, ready to paste into a message.
- **Undoing something Phoenix did** — Settings → Diagnostics lists recent
  jobs; where one can be undone (a VPN connection, an agent install) the row
  offers **Undo**, which asks once more before it runs.

## More Information

- **Releases** — Version history, system requirements, and how updates work.
- **LICENSE** — The GNU General Public License v2 (or later) that Phoenix is
  distributed under.
- **LICENSE-3rd-Party** — The full third-party software bill of materials
  (SBOM): every bundled component with its version and license.

## About

Phoenix AI EndPoint Detection and Response (AI EDR)
for Windows, macOS, and Linux desktops.

Copyright (C) 2025 Phoenix

This program is free software under the terms of the GNU General Public
License v2 or later. Phoenix comes with ABSOLUTELY NO WARRANTY.

See the **LICENSE** entry in the dropdown above for full details.
