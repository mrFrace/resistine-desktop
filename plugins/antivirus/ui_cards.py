"""Secondary UI card builders for the Antivirus plugin.

Builds Quarantine, Whitelist, Scan Exclusions, SIEM Forwarding,
and Signature Database / Updates cards.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import customtkinter
from customtkinter import ThemeManager

from plugins.antivirus.theme import (
    add_separator,
    font,
    make_card,
    section_title,
)


def _muted():
    return ThemeManager.theme.get("Theme", {}).get("text_secondary")


def _btn_border():
    return ThemeManager.theme.get("CTkButton", {}).get("border_color")


def _btn_hover():
    return ThemeManager.theme.get("CTkButton", {}).get("hover_color")


def _ok_text():
    return ThemeManager.theme.get("Theme", {}).get("success_color", "#2ecc71")


# ── 4a. Quarantine (standalone, main view) ──────────────


def build_quarantine_card(plugin, parent, row):
    """Standalone quarantine card (full-width, main view)."""
    card = make_card(parent, row)
    card.grid_columnconfigure(0, weight=1)

    section_title(card, "Quarantine").grid(
        row=0, column=0, padx=16, pady=(14, 3), sticky="w",
    )
    add_separator(card, 1)

    plugin._quarantine_frame = customtkinter.CTkFrame(
        card, fg_color="transparent",
    )
    plugin._quarantine_frame.grid(
        row=2, column=0, padx=16, pady=(8, 14), sticky="ew",
    )
    plugin._quarantine_frame.grid_columnconfigure(0, weight=1)

    customtkinter.CTkLabel(
        plugin._quarantine_frame, text="No threats quarantined",
        font=font(12), text_color=_muted(),
    ).grid(row=0, column=0, sticky="w")
    return row + 1


# ── 4b. Whitelist (standalone, settings view) ───────────


def build_whitelist_card(plugin, parent, row):
    """Standalone whitelist card (full-width, settings view)."""
    card = make_card(parent, row)
    card.grid_columnconfigure(0, weight=1)

    hdr = customtkinter.CTkFrame(card, fg_color="transparent")
    hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 3))
    hdr.grid_columnconfigure(0, weight=1)

    section_title(hdr, "Whitelist").grid(row=0, column=0, sticky="w")

    customtkinter.CTkButton(
        hdr, text="+ Add", width=60, height=26, corner_radius=6,
        font=font(11), fg_color="transparent", border_width=1,
        border_color=_btn_border(), text_color=_btn_border(),
        hover_color=_btn_hover(),
        command=lambda: plugin._on_action("whitelist_add"),
    ).grid(row=0, column=1, sticky="e")

    add_separator(card, 1)

    plugin._whitelist_frame = customtkinter.CTkFrame(
        card, fg_color="transparent",
    )
    plugin._whitelist_frame.grid(
        row=2, column=0, padx=16, pady=(8, 14), sticky="ew",
    )
    plugin._whitelist_frame.grid_columnconfigure(0, weight=1)

    customtkinter.CTkLabel(
        plugin._whitelist_frame, text="No whitelisted paths",
        font=font(12), text_color=_muted(),
    ).grid(row=0, column=0, sticky="w")
    return row + 1


# ── 5. Scan Exclusions ─────────────────────────────────


def build_scan_exclusions(plugin, parent, row):
    """Build the Scan Exclusions card (extension filter + max file size)."""
    card = make_card(parent, row)
    card.grid_columnconfigure(0, weight=1)

    customtkinter.CTkLabel(
        card, text="Scan Exclusions", font=font(14, bold=True),
    ).grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 6), sticky="w")

    add_separator(card, 1)

    # ── Extension exclusions ──
    customtkinter.CTkLabel(
        card, text="Skip File Extensions", font=font(12),
        text_color=_muted(),
    ).grid(row=2, column=0, columnspan=2, padx=16, pady=(8, 4), sticky="w")

    add_row = customtkinter.CTkFrame(card, fg_color="transparent")
    add_row.grid(
        row=3, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4),
    )
    add_row.grid_columnconfigure(0, weight=1)

    plugin._ext_entry = customtkinter.CTkEntry(
        add_row, height=28, placeholder_text=".iso, .vmdk, .log",
        font=font(11),
    )
    plugin._ext_entry.grid(row=0, column=0, sticky="ew", padx=(0, 4))
    plugin._ext_entry.bind("<Return>", lambda e: plugin._add_excluded_extension())

    customtkinter.CTkButton(
        add_row, text="+ Add", width=60, height=28, corner_radius=6,
        font=font(11), fg_color="transparent", border_width=1,
        border_color=_btn_border(), text_color=_btn_border(),
        hover_color=_btn_hover(),
        command=plugin._add_excluded_extension,
    ).grid(row=0, column=1)

    plugin._exclusions_frame = customtkinter.CTkFrame(
        card, fg_color="transparent",
    )
    plugin._exclusions_frame.grid(
        row=4, column=0, columnspan=2, padx=16, pady=(0, 8), sticky="ew",
    )
    plugin._exclusions_frame.grid_columnconfigure(0, weight=1)

    add_separator(card, 5)

    # ── Max file size ──
    size_row = customtkinter.CTkFrame(card, fg_color="transparent")
    size_row.grid(
        row=6, column=0, columnspan=2, sticky="ew", padx=16, pady=(8, 14),
    )
    size_row.grid_columnconfigure(0, weight=1)

    customtkinter.CTkLabel(
        size_row, text="Max File Size", font=font(12),
    ).grid(row=0, column=0, sticky="w")

    right = customtkinter.CTkFrame(size_row, fg_color="transparent")
    right.grid(row=0, column=1, sticky="e")

    plugin._size_entry = customtkinter.CTkEntry(
        right, width=70, height=28, font=font(11), justify="right",
    )
    plugin._size_entry.grid(row=0, column=0)
    plugin._size_entry.insert(0, "0")
    plugin._size_entry.bind("<Return>", lambda e: plugin._save_max_file_size())
    plugin._size_entry.bind("<FocusOut>", lambda e: plugin._save_max_file_size())
    plugin._size_entry.bind("<KeyRelease>", lambda e: plugin._debounced_save_max_file_size())

    customtkinter.CTkLabel(
        right, text="MB", font=font(11), text_color=_muted(),
    ).grid(row=0, column=1, padx=(4, 0))

    customtkinter.CTkLabel(
        size_row, text="0 = no limit",
        font=font(10), text_color=_muted(),
    ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

    return row + 1


# ── 6. SIEM Forwarding ─────────────────────────────────


def build_siem_card(plugin, parent, row):
    """Build the SIEM Forwarding card (threat log + Wazuh setup)."""
    from plugins.antivirus.threat_log import (
        get_log_display, is_forwarding_enabled, is_wazuh_installed,
    )

    card = make_card(parent, row)
    card.grid_columnconfigure(0, weight=1)

    customtkinter.CTkLabel(
        card, text="SIEM Forwarding", font=font(14, bold=True),
    ).grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 6), sticky="w")

    add_separator(card, 1)

    # Threat log source
    customtkinter.CTkLabel(
        card, text="Threat Log", text_color=_muted(), font=font(12),
    ).grid(row=2, column=0, padx=16, pady=(8, 0), sticky="w")

    customtkinter.CTkLabel(
        card, text=get_log_display(), font=font(10),
        text_color=_muted(), wraplength=340, justify="left",
    ).grid(row=3, column=0, columnspan=2, padx=16, pady=(2, 8), sticky="w")

    add_separator(card, 4)

    # Forwarding switch. It's auto-enabled when the endpoint agent installs
    # (the installer injects the Defender localfile on Windows), so a present
    # agent shows it on. With no agent, flipping it on routes the user to the
    # Endpoint page to install the agent first (handled in _on_forwarding_toggle).
    installed = is_wazuh_installed()
    forwarding_on = is_forwarding_enabled()

    plugin._siem_switch = customtkinter.CTkSwitch(
        card, text="Forward AV detections to the SIEM",
        font=font(12), command=plugin._on_forwarding_toggle,
        onvalue=1, offvalue=0,
    )
    if forwarding_on:
        plugin._siem_switch.select()
    else:
        plugin._siem_switch.deselect()
    plugin._siem_switch.grid(
        row=5, column=0, columnspan=2, padx=16, pady=(8, 2), sticky="w",
    )

    if forwarding_on:
        _status_text, _status_color = "Forwarding active", _ok_text()
    elif installed:
        _status_text, _status_color = (
            "Ready — turn on to forward AV detections", _muted())
    else:
        _status_text, _status_color = (
            "Install the endpoint agent to enable forwarding", _muted())
    plugin._siem_status_label = customtkinter.CTkLabel(
        card, text=_status_text, font=font(11), text_color=_status_color,
    )
    plugin._siem_status_label.grid(
        row=6, column=0, columnspan=2, padx=16, pady=(0, 14), sticky="w",
    )

    return row + 1


def _build_db_info_rows(plugin, card, start_row):
    from plugins.antivirus import clamav

    db_rows = [
        ("Engine", clamav.engine_name()),
        ("Signatures", "\u2014"),
        ("Last Updated", "\u2014"),
    ]
    plugin._db_labels = {}
    r = start_row
    for label, value in db_rows:
        customtkinter.CTkLabel(
            card, text=label, text_color=_muted(), font=font(12),
        ).grid(row=r, column=0, padx=16, pady=(4, 0), sticky="w")
        val_lbl = customtkinter.CTkLabel(
            card, text=value, font=font(12, bold=True),
        )
        val_lbl.grid(row=r, column=1, padx=16, pady=(4, 0), sticky="e")
        plugin._db_labels[label] = val_lbl
        r += 1
    return r


def _build_auto_update_toggle(plugin, card, row):
    import platform

    auto_row = customtkinter.CTkFrame(card, fg_color="transparent")
    auto_row.grid(
        row=row, column=0, columnspan=2, sticky="ew", padx=16, pady=(6, 0),
    )
    auto_row.grid_columnconfigure(0, weight=1)

    left = customtkinter.CTkFrame(auto_row, fg_color="transparent")
    left.grid(row=0, column=0, sticky="w")

    customtkinter.CTkLabel(
        left, text="Auto-update signatures", font=font(12),
    ).grid(row=0, column=0, sticky="w")

    if platform.system() == "Darwin":
        # macOS: a root LaunchDaemon updates signatures even when the app is
        # closed, so auto-update is always on \u2014 no toggle to defeat its
        # purpose. Show a read-only "Automatic" status instead of a switch.
        customtkinter.CTkLabel(
            left, text="Checks every ~4 hours, even when the app is closed",
            font=font(11), text_color=_muted(),
        ).grid(row=1, column=0, sticky="w")
        customtkinter.CTkLabel(
            auto_row, text="Automatic", font=font(12), text_color=_muted(),
        ).grid(row=0, column=1, sticky="e", pady=4)
        plugin._auto_update_switch = None
        return row + 1

    # Linux/Windows: the in-process scheduler is the only updater, and the
    # user-facing toggle is retained unchanged.
    customtkinter.CTkLabel(
        left, text="Daily around 4:00 AM (\u00b12 hrs)",
        font=font(11), text_color=_muted(),
    ).grid(row=1, column=0, sticky="w")

    plugin._auto_update_switch = customtkinter.CTkSwitch(
        auto_row, text="", width=44,
        command=plugin._toggle_auto_update,
        onvalue=True, offvalue=False,
    )
    if plugin._auto_update_on:
        plugin._auto_update_switch.select()
    plugin._auto_update_switch.grid(row=0, column=1, sticky="e", pady=4)
    return row + 1


def build_db_info_card(plugin, parent, row):
    """Read-only signature database info card (main view)."""
    card = make_card(parent, row)
    card.grid_columnconfigure(1, weight=1)

    section_title(card, "Signature Database").grid(
        row=0, column=0, columnspan=2, padx=16, pady=(14, 3), sticky="w",
    )

    add_separator(card, 1)
    _build_db_info_rows(plugin, card, start_row=2)

    customtkinter.CTkFrame(card, height=8, fg_color="transparent").grid(
        row=5, column=0, columnspan=2,
    )
    return row + 1


def build_sig_updates_settings_card(plugin, parent, row):
    """Auto-update toggle + Update Now button (settings view)."""
    card = make_card(parent, row)
    card.grid_columnconfigure(1, weight=1)

    section_title(card, "Signature Updates").grid(
        row=0, column=0, columnspan=2, padx=16, pady=(14, 3), sticky="w",
    )

    add_separator(card, 1)

    r = _build_auto_update_toggle(plugin, card, 2)

    update_btn = customtkinter.CTkButton(
        card, text="Update Now", height=30, corner_radius=8,
        font=font(12), fg_color="transparent", border_width=1,
        border_color=_btn_border(), text_color=_btn_border(),
        hover_color=_btn_hover(),
        command=lambda: plugin._on_action("update_sigs"),
    )
    update_btn.grid(
        row=r, column=0, columnspan=2, padx=16, pady=(8, 14), sticky="ew",
    )
    plugin._action_buttons["update_sigs"] = update_btn
    return row + 1
