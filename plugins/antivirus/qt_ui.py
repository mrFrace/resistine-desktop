"""PyQt6 UI builders for the Antivirus plugin.

Faithful port of the CustomTkinter screen (ui_builders.py / ui_cards.py /
ui_settings.py). Each builder appends a "card" QFrame (objectName "Surface")
into a column layout, mirroring the original section order and controls 1:1.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from gui.qt_widgets import load_icon, resource


# ── Small shared helpers ───────────────────────────────────


def card(object_name: str = "Surface") -> tuple[QFrame, QVBoxLayout]:
    """A bordered, rounded surface with a vertical body layout."""
    frame = QFrame()
    frame.setObjectName(object_name)
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(16, 12, 16, 16)
    lay.setSpacing(8)
    return frame, lay


def section_title(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"font-size: 12px; font-weight: 700; "
        f"color: {theme.color('sidebar_active_text')};"
    )
    return lbl


def divider() -> QFrame:
    div = QFrame()
    div.setFixedHeight(1)
    div.setObjectName("Divider")
    return div


def muted(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(f"color: {theme.color('text_secondary')};")
    return lbl


def secondary_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("Secondary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


# ── 1. Protection Status Banner ────────────────────────────


def build_status_banner(plugin, col: QVBoxLayout) -> None:
    """VPN-style status card: title, subtitle, action button, gear, progress."""
    frame = QFrame()
    frame.setObjectName("AvBanner")
    frame.setStyleSheet(_banner_qss("warn"))
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(22, 18, 16, 18)
    outer.setSpacing(8)

    top = QHBoxLayout()
    top.setSpacing(10)

    text_col = QVBoxLayout()
    text_col.setSpacing(4)
    # Title + subtitle formatted identically to the VPN status card
    # ("Connected" / "All traffic …"): 28px coloured title, 12px muted subtitle,
    # transparent backgrounds. The title colour is set per state in
    # _apply_realtime_status_ui via banner_title_color().
    plugin._banner_label = QLabel("Checking...")
    plugin._banner_label.setStyleSheet(
        f"color: {banner_title_color('warn')}; font-size: 28px; "
        f"font-weight: 700; background: transparent;"
    )
    text_col.addWidget(plugin._banner_label)

    _sub_color = "#AAAAAA" if theme.is_dark() else "#555555"
    plugin._banner_subtitle = QLabel("Checking protection status...")
    plugin._banner_subtitle.setWordWrap(True)
    plugin._banner_subtitle.setStyleSheet(
        f"color: {_sub_color}; font-size: 12px; background: transparent;"
    )
    plugin._banner_subtitle.setMaximumWidth(360)
    text_col.addWidget(plugin._banner_subtitle)
    top.addLayout(text_col, 1)

    plugin._banner_action_btn = QPushButton("Open Settings")
    plugin._banner_action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    plugin._banner_action_btn.setMinimumWidth(130)
    plugin._banner_action_btn.hide()
    top.addWidget(plugin._banner_action_btn,
                  0, Qt.AlignmentFlag.AlignTop)

    # A real gear icon (the Settings plugin's glyph) rather than the ⚙ emoji,
    # which renders inconsistently / clipped across platforms.
    plugin._settings_gear_btn = QPushButton()
    plugin._settings_gear_btn.setIcon(load_icon(
        resource("plugins", "settings", "settings_light.png"),
        resource("plugins", "settings", "settings_dark.png")))
    plugin._settings_gear_btn.setIconSize(QSize(20, 20))
    plugin._settings_gear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    plugin._settings_gear_btn.setFixedSize(48, 48)
    plugin._settings_gear_btn.setStyleSheet(
        "QPushButton { background-color: transparent; border: none; }"
    )
    plugin._settings_gear_btn.clicked.connect(plugin._show_settings_view)
    top.addWidget(plugin._settings_gear_btn,
                  0, Qt.AlignmentFlag.AlignTop)

    outer.addLayout(top)

    plugin._banner_progress = QProgressBar()
    plugin._banner_progress.setTextVisible(False)
    plugin._banner_progress.setFixedHeight(4)
    plugin._banner_progress.setRange(0, 0)  # indeterminate
    plugin._banner_progress.hide()
    outer.addWidget(plugin._banner_progress)

    plugin._banner_frame = frame
    col.addWidget(frame)


def banner_title_color(kind: str) -> str:
    """Title text colour per state — same palette as the VPN status card."""
    if kind == "ok":
        return "#2CC985" if theme.is_dark() else "#1B7A3E"
    if kind == "error":
        return "#FF4040" if theme.is_dark() else "#C5221F"
    return "#FBBF24" if theme.is_dark() else "#B45309"  # warn (amber)


def _banner_qss(kind: str) -> str:
    """Background + radius for the banner card — same tints as the VPN card."""
    if kind == "ok":
        bg = "#1A2E1F" if theme.is_dark() else "#E8F5E9"
    elif kind == "error":
        bg = "#2E1A1A" if theme.is_dark() else "#FDEDEC"
    else:
        bg = theme.color("protect_warn_bg")
    return (
        f"#AvBanner {{ background-color: {bg}; border: none; "
        f"border-radius: 12px; }}"
    )


# ── 2. Scan card ───────────────────────────────────────────


def build_scan_card(plugin, col: QVBoxLayout) -> None:
    frame, lay = card()
    lay.addWidget(section_title("Scan"))
    lay.addWidget(divider())
    lay.addSpacing(2)

    row = QHBoxLayout()
    row.setSpacing(8)
    for text, key in (("Scan…", "scan"), ("Scan Computer", "scan_computer")):
        btn = QPushButton(text)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda _=False, k=key: plugin._on_action(k))
        row.addWidget(btn, 1)
        plugin._action_buttons[key] = btn
    lay.addLayout(row)
    col.addWidget(frame)


# ── 3. Scan Activity card ──────────────────────────────────


def build_scan_activity(plugin, col: QVBoxLayout) -> None:
    frame, lay = card()

    header = QHBoxLayout()
    header.setSpacing(8)
    header.addWidget(section_title("Scan Activity"))
    header.addStretch(1)

    plugin._scan_status_label = QLabel("No scans yet")
    plugin._scan_status_label.setStyleSheet(
        f"font-size: 11px; color: {theme.color('text_secondary')};"
    )
    header.addWidget(plugin._scan_status_label)

    cancel_btn = QPushButton("Cancel")
    cancel_btn.setObjectName("Danger")
    cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    cancel_btn.setStyleSheet(
        "QPushButton { background-color: transparent; border: 1px solid "
        "#DC2626; color: #DC2626; border-radius: 6px; padding: 3px 12px; "
        "font-size: 11px; font-weight: 600; }"
    )
    cancel_btn.clicked.connect(plugin._cancel_scan)
    cancel_btn.hide()
    header.addWidget(cancel_btn)
    plugin._action_buttons["cancel_scan"] = cancel_btn
    lay.addLayout(header)

    lay.addWidget(divider())

    plugin._scan_progress = QProgressBar()
    plugin._scan_progress.setTextVisible(False)
    plugin._scan_progress.setFixedHeight(4)
    plugin._scan_progress.setRange(0, 1000)
    plugin._scan_progress.setValue(0)
    plugin._scan_progress.hide()
    lay.addWidget(plugin._scan_progress)

    plugin._scan_log = QPlainTextEdit()
    plugin._scan_log.setReadOnly(True)
    plugin._scan_log.setFixedHeight(140)
    plugin._scan_log.setStyleSheet(
        'font-family: "Courier New", monospace; font-size: 11px;'
    )
    lay.addWidget(plugin._scan_log)
    col.addWidget(frame)


# ── 4. Quarantine card (main view) ─────────────────────────


def build_quarantine_card(plugin, col: QVBoxLayout) -> None:
    frame, lay = card()
    lay.addWidget(section_title("Quarantine"))
    lay.addWidget(divider())

    plugin._quarantine_frame = QWidget()
    plugin._quarantine_frame.setObjectName("Transparent")
    qlay = QVBoxLayout(plugin._quarantine_frame)
    qlay.setContentsMargins(0, 0, 0, 0)
    qlay.setSpacing(2)
    plugin._quarantine_layout = qlay
    qlay.addWidget(muted("No threats quarantined"))
    lay.addWidget(plugin._quarantine_frame)
    col.addWidget(frame)


# ── 5. Signature Database card (main view) ─────────────────


def build_db_info_card(plugin, col: QVBoxLayout) -> None:
    from plugins.antivirus import clamav

    frame, lay = card()
    lay.addWidget(section_title("Signature Database"))
    lay.addWidget(divider())

    try:
        engine = clamav.engine_name()
    except Exception:
        engine = "ClamAV"

    plugin._db_labels = {}
    for label, value in (
        ("Engine", engine),
        ("Signatures", "—"),
        ("Last Updated", "—"),
    ):
        r = QHBoxLayout()
        r.addWidget(muted(label))
        r.addStretch(1)
        val = QLabel(value)
        val.setStyleSheet("font-weight: 700;")
        val.setWordWrap(True)  # wrap instead of clipping on narrow windows
        r.addWidget(val, 1, Qt.AlignmentFlag.AlignRight)
        lay.addLayout(r)
        plugin._db_labels[label] = val
    col.addWidget(frame)
    col.addStretch(1)  # keep cards top-packed; slack goes below the last card


# ── Settings sub-view ──────────────────────────────────────


def build_settings_header(plugin, col: QVBoxLayout) -> None:
    row = QHBoxLayout()
    back = secondary_button("←  Back")
    back.setStyleSheet(
        "QPushButton { background-color: transparent; border: none; "
        f"color: {theme.color('text_secondary')}; font-size: 12px; }}"
    )
    back.clicked.connect(plugin._show_main_view)
    row.addWidget(back, 0, Qt.AlignmentFlag.AlignLeft)
    row.addStretch(1)
    title = QLabel("Settings")
    title.setStyleSheet("font-size: 18px; font-weight: 700;")
    row.addWidget(title)
    row.addStretch(1)
    spacer = QWidget()
    spacer.setObjectName("Transparent")
    spacer.setFixedWidth(80)
    row.addWidget(spacer)
    col.addLayout(row)


def build_siem_card(plugin, col: QVBoxLayout) -> None:
    from plugins.antivirus.threat_log import get_log_display, is_wazuh_installed

    frame, lay = card()
    title = QLabel("SIEM Forwarding")
    title.setStyleSheet("font-size: 14px; font-weight: 700;")
    lay.addWidget(title)
    lay.addWidget(divider())

    lay.addWidget(muted("Threat Log"))
    try:
        disp = get_log_display()
    except Exception:
        disp = ""
    path_lbl = muted(disp)
    path_lbl.setStyleSheet(
        f"font-size: 10px; color: {theme.color('text_secondary')};"
    )
    lay.addWidget(path_lbl)
    lay.addWidget(divider())

    wazuh = False
    try:
        wazuh = is_wazuh_installed()
    except Exception:
        wazuh = False

    if wazuh:
        plugin._siem_status_label = QLabel("Wazuh agent detected")
        plugin._siem_status_label.setStyleSheet("color: #2ecc71;")
        lay.addWidget(plugin._siem_status_label)

        plugin._siem_btn = secondary_button("Configure Forwarding")
        plugin._siem_btn.clicked.connect(plugin._setup_wazuh_forwarding)
        lay.addWidget(plugin._siem_btn)
    else:
        lay.addWidget(muted("Wazuh agent not installed"))
        lay.addWidget(muted("Threat events are logged locally."))
    col.addWidget(frame)


def build_scan_exclusions(plugin, col: QVBoxLayout) -> None:
    frame, lay = card()
    title = QLabel("Scan Exclusions")
    title.setStyleSheet("font-size: 14px; font-weight: 700;")
    lay.addWidget(title)
    lay.addWidget(divider())

    lay.addWidget(muted("Skip File Extensions"))

    add_row = QHBoxLayout()
    add_row.setSpacing(4)
    plugin._ext_entry = QLineEdit()
    plugin._ext_entry.setPlaceholderText(".iso, .vmdk, .log")
    plugin._ext_entry.returnPressed.connect(plugin._add_excluded_extension)
    add_row.addWidget(plugin._ext_entry, 1)
    add_btn = secondary_button("+ Add")
    add_btn.clicked.connect(plugin._add_excluded_extension)
    add_row.addWidget(add_btn)
    lay.addLayout(add_row)

    plugin._exclusions_frame = QWidget()
    plugin._exclusions_frame.setObjectName("Transparent")
    elay = QVBoxLayout(plugin._exclusions_frame)
    elay.setContentsMargins(0, 0, 0, 0)
    elay.setSpacing(2)
    plugin._exclusions_layout = elay
    lay.addWidget(plugin._exclusions_frame)

    lay.addWidget(divider())

    size_row = QHBoxLayout()
    size_row.addWidget(QLabel("Max File Size"))
    size_row.addStretch(1)
    plugin._size_entry = QLineEdit()
    plugin._size_entry.setFixedWidth(70)
    plugin._size_entry.setText("0")
    plugin._size_entry.setAlignment(Qt.AlignmentFlag.AlignRight)
    plugin._size_entry.editingFinished.connect(plugin._save_max_file_size)
    plugin._size_entry.textEdited.connect(
        lambda _=None: plugin._debounced_save_max_file_size())
    size_row.addWidget(plugin._size_entry)
    size_row.addWidget(muted("MB"))
    lay.addLayout(size_row)

    hint = muted("0 = no limit")
    hint.setStyleSheet(
        f"font-size: 10px; color: {theme.color('text_secondary')};"
    )
    lay.addWidget(hint)
    col.addWidget(frame)


def build_whitelist_card(plugin, col: QVBoxLayout) -> None:
    frame, lay = card()

    header = QHBoxLayout()
    header.addWidget(section_title("Whitelist"))
    header.addStretch(1)
    add_btn = secondary_button("+ Add")
    add_btn.clicked.connect(lambda: plugin._on_action("whitelist_add"))
    header.addWidget(add_btn)
    lay.addLayout(header)
    lay.addWidget(divider())

    plugin._whitelist_frame = QWidget()
    plugin._whitelist_frame.setObjectName("Transparent")
    wlay = QVBoxLayout(plugin._whitelist_frame)
    wlay.setContentsMargins(0, 0, 0, 0)
    wlay.setSpacing(2)
    plugin._whitelist_layout = wlay
    wlay.addWidget(muted("No whitelisted paths"))
    lay.addWidget(plugin._whitelist_frame)
    col.addWidget(frame)


def build_sig_updates_settings_card(plugin, col: QVBoxLayout) -> None:
    from PyQt6.QtWidgets import QCheckBox

    frame, lay = card()
    lay.addWidget(section_title("Signature Updates"))
    lay.addWidget(divider())

    auto_row = QHBoxLayout()
    left = QVBoxLayout()
    left.setSpacing(0)
    left.addWidget(QLabel("Auto-update signatures"))
    sub = muted("Daily around 4:00 AM (±2 hrs)")
    sub.setStyleSheet(
        f"font-size: 11px; color: {theme.color('text_secondary')};"
    )
    left.addWidget(sub)
    auto_row.addLayout(left, 1)

    plugin._auto_update_switch = QCheckBox()
    plugin._auto_update_switch.setChecked(bool(plugin._auto_update_on))
    plugin._auto_update_switch.toggled.connect(plugin._toggle_auto_update)
    auto_row.addWidget(plugin._auto_update_switch,
                       0, Qt.AlignmentFlag.AlignRight)
    lay.addLayout(auto_row)

    update_btn = secondary_button("Update Now")
    update_btn.clicked.connect(lambda: plugin._on_action("update_sigs"))
    lay.addWidget(update_btn)
    plugin._action_buttons["update_sigs"] = update_btn
    col.addWidget(frame)


def build_settings_view(plugin, col: QVBoxLayout) -> None:
    build_settings_header(plugin, col)
    build_siem_card(plugin, col)
    build_scan_exclusions(plugin, col)
    build_whitelist_card(plugin, col)
    build_sig_updates_settings_card(plugin, col)
    col.addStretch(1)
