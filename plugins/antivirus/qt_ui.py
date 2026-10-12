"""PyQt6 UI builders for the Antivirus plugin.

Flat page layout (gui/page_kit.py): a header with the status pill, then
sections of sidebar-style action rows, plain lists and label/value rows.
Each builder appends its section to a :class:`gui.page_kit.Page`.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.page_kit import (
    KVList,
    MenuRow,
    Page,
    PageHeader,
    RowList,
    SettingRow,
    icon_button,
)
from gui.page_kit import muted as _muted
from gui.toggle import ToggleSwitch


def muted(text: str) -> QLabel:
    return _muted(text)


def secondary_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("Secondary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


def _list_box() -> tuple[QWidget, QVBoxLayout]:
    """A plain container whose rows main.py fills (_refresh_* helpers)."""
    box = QWidget()
    box.setObjectName("Transparent")
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(0)
    return box, lay


# ── Main view ──────────────────────────────────────────────


def build_status_banner(plugin, page: Page) -> None:
    """Header: title + status pill, subtitle, action button, gear, and the
    setup progress bar under it."""
    header = PageHeader("Antivirus", "Checking protection status...",
                        ("warning", "Checking..."))
    plugin._banner_action_btn = QPushButton("Open Settings")
    plugin._banner_action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    plugin._banner_action_btn.hide()
    header.add_control(plugin._banner_action_btn)
    plugin._settings_gear_btn = header.add_control(
        icon_button("settings", "Antivirus settings"))
    plugin._settings_gear_btn.clicked.connect(plugin._show_settings_view)
    page.add(header)

    plugin._banner_progress = QProgressBar()
    plugin._banner_progress.setTextVisible(False)
    plugin._banner_progress.setFixedHeight(4)
    plugin._banner_progress.setRange(0, 0)  # indeterminate
    plugin._banner_progress.hide()
    page.spacing(10)
    page.add(plugin._banner_progress)

    plugin._banner_frame = header
    plugin._banner_label = header.pill
    plugin._banner_subtitle = header.subtitle


def set_status_pill(header: PageHeader, kind: str, text: str) -> None:
    """Banner state (ok / warn / error) -> header status pill."""
    header.set_status({"warn": "warning"}.get(kind, kind), text)


def build_scan_card(plugin, page: Page) -> None:
    page.section("Actions")
    for key, icon, title, hint in (
        ("scan", "folder-search", "Scan files or a folder…",
         "Pick what to check"),
        ("scan_computer", "monitor", "Scan computer",
         "Full scan of your home folder"),
        ("update_sigs", "refresh-cw", "Update signatures",
         "Download the latest malware definitions"),
    ):
        row = MenuRow(icon, title, hint)
        row.clicked.connect(lambda k=key: plugin._on_action(k))
        page.add(row)
        plugin._action_buttons[key] = row


def build_scan_activity(plugin, page: Page) -> None:
    page.spacing(28)
    header = QHBoxLayout()
    header.setSpacing(8)
    from gui.page_kit import section_heading
    header.addWidget(section_heading("Activity"))
    header.addStretch(1)
    cancel_btn = QPushButton("Cancel scan")
    cancel_btn.setObjectName("Link")
    cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    cancel_btn.clicked.connect(plugin._cancel_scan)
    cancel_btn.hide()
    header.addWidget(cancel_btn)
    plugin._action_buttons["cancel_scan"] = cancel_btn
    page.add_layout(header)
    page.spacing(8)

    plugin._scan_status_label = muted("No scans yet")
    page.add(plugin._scan_status_label)

    plugin._scan_progress = QProgressBar()
    plugin._scan_progress.setTextVisible(False)
    plugin._scan_progress.setFixedHeight(4)
    plugin._scan_progress.setRange(0, 1000)
    plugin._scan_progress.setValue(0)
    plugin._scan_progress.hide()
    page.spacing(8)
    page.add(plugin._scan_progress)

    # Hidden until there is something to show (main._log_append).
    plugin._scan_log = QPlainTextEdit()
    plugin._scan_log.setReadOnly(True)
    plugin._scan_log.setFixedHeight(140)
    plugin._scan_log.setStyleSheet(
        'font-family: "Courier New", monospace; font-size: 11px;'
    )
    plugin._scan_log.hide()
    page.add(plugin._scan_log)


def build_quarantine_card(plugin, page: Page) -> None:
    page.section("Quarantine")
    plugin._quarantine_frame, plugin._quarantine_layout = _list_box()
    plugin._quarantine_layout.addWidget(muted("No threats quarantined"))
    page.add(plugin._quarantine_frame)


def build_db_info_card(plugin, page: Page) -> None:
    from plugins.antivirus import clamav

    page.section("Signature database")
    try:
        engine = clamav.engine_name()
    except Exception:
        engine = "ClamAV"
    kv = KVList([("Engine", engine), ("Signatures", "—"),
                 ("Last Updated", "—")])
    plugin._db_labels = kv.values
    page.add(kv)


def build_main_view(plugin) -> Page:
    page = Page()
    build_status_banner(plugin, page)
    build_scan_card(plugin, page)
    build_scan_activity(plugin, page)
    build_quarantine_card(plugin, page)
    build_db_info_card(plugin, page)
    page.stretch()
    return page


# ── Settings sub-view ──────────────────────────────────────


def build_settings_header(plugin, page: Page) -> None:
    back = QPushButton("‹  Antivirus")
    back.setObjectName("Link")
    back.setCursor(Qt.CursorShape.PointingHandCursor)
    back.clicked.connect(plugin._show_main_view)
    page.add(back).setSizePolicy(back.sizePolicy().horizontalPolicy().Maximum,
                                 back.sizePolicy().verticalPolicy())
    page.spacing(6)
    page.add(PageHeader("Settings", "Signature updates, exclusions and "
                        "forwarding for the antivirus"))


def build_sig_updates_settings_card(plugin, page: Page) -> None:
    page.section("Signature updates")
    plugin._auto_update_switch = ToggleSwitch()
    plugin._auto_update_switch.setChecked(bool(plugin._auto_update_on))
    plugin._auto_update_switch.toggled.connect(plugin._toggle_auto_update)
    rows = RowList()
    rows.add_row(SettingRow("Auto-update signatures",
                            "Daily around 4:00 AM (±2 hrs)",
                            plugin._auto_update_switch))
    page.add(rows)


def build_scan_exclusions(plugin, page: Page) -> None:
    page.section("Scan exclusions")
    rows = RowList()

    add = QWidget()
    add.setObjectName("Transparent")
    add_row = QHBoxLayout(add)
    add_row.setContentsMargins(0, 0, 0, 0)
    add_row.setSpacing(8)
    plugin._ext_entry = QLineEdit()
    plugin._ext_entry.setPlaceholderText(".iso, .vmdk, .log")
    plugin._ext_entry.returnPressed.connect(plugin._add_excluded_extension)
    add_row.addWidget(plugin._ext_entry, 1)
    add_btn = secondary_button("Add")
    add_btn.clicked.connect(plugin._add_excluded_extension)
    add_row.addWidget(add_btn)
    ext = SettingRow("Skip file extensions",
                     "Files with these extensions are never scanned",
                     add, stacked=True)
    plugin._exclusions_frame, plugin._exclusions_layout = _list_box()
    ext.body.addWidget(plugin._exclusions_frame)
    rows.add_row(ext)

    size = QWidget()
    size.setObjectName("Transparent")
    size_row = QHBoxLayout(size)
    size_row.setContentsMargins(0, 0, 0, 0)
    size_row.setSpacing(6)
    plugin._size_entry = QLineEdit()
    plugin._size_entry.setFixedWidth(70)
    plugin._size_entry.setText("0")
    plugin._size_entry.setAlignment(Qt.AlignmentFlag.AlignRight)
    plugin._size_entry.editingFinished.connect(plugin._save_max_file_size)
    plugin._size_entry.textEdited.connect(
        lambda _=None: plugin._debounced_save_max_file_size())
    size_row.addWidget(plugin._size_entry)
    size_row.addWidget(muted("MB"))
    rows.add_row(SettingRow("Max file size", "0 = no limit", size))
    page.add(rows)


def build_whitelist_card(plugin, page: Page) -> None:
    page.section("Whitelist")
    plugin._whitelist_frame, plugin._whitelist_layout = _list_box()
    plugin._whitelist_layout.addWidget(muted("No whitelisted paths"))
    page.add(plugin._whitelist_frame)
    page.spacing(4)
    page.add(MenuRow("plus", "Add folder…", "Skip a trusted folder when scanning",
                     on_click=lambda: plugin._on_action("whitelist_add")))


def build_siem_card(plugin, page: Page) -> None:
    from plugins.antivirus.threat_log import get_log_display, is_wazuh_installed

    page.section("SIEM forwarding")
    try:
        disp = get_log_display()
    except Exception:
        disp = ""
    page.add(KVList([("Threat log", disp)]))

    try:
        wazuh = is_wazuh_installed()
    except Exception:
        wazuh = False
    page.spacing(4)
    if wazuh:
        plugin._siem_btn = MenuRow("activity", "Configure Forwarding",
                                   "Wazuh agent detected")
        plugin._siem_btn.clicked.connect(plugin._setup_wazuh_forwarding)
        # _refresh_siem_switch updates the status line via setText.
        plugin._siem_status_label = plugin._siem_btn._hint
        page.add(plugin._siem_btn)
    else:
        page.add(muted("Wazuh agent not installed — threat events are "
                       "logged locally."))


def build_settings_view(plugin) -> Page:
    page = Page()
    build_settings_header(plugin, page)
    build_sig_updates_settings_card(plugin, page)
    build_scan_exclusions(plugin, page)
    build_whitelist_card(plugin, page)
    build_siem_card(plugin, page)
    page.stretch()
    return page
