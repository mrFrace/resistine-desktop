# -*- coding: utf-8 -*-
# @file plugins/login/setup_wizard.py
# Description: Unified post-login customer setup wizard (PyQt6).
#
# One screen, one guided flow. After sign-in the user lands here and a single
# "Get Protected" button walks them through every permission and installation
# their operating system needs — macOS VPN extension approval, antivirus +
# Full Disk Access, endpoint monitoring; the Windows/Linux equivalents — so
# they never have to hunt through the app enabling things by hand. A Skip
# button is always available.
#
# The wizard is intentionally plugin-agnostic: all platform specifics live in
# setup_steps.py. This module only sequences steps and renders their state.
#
# Author: Phoenix Team
# Copyright: Phoenix (c) 2025
# Licensed under the GNU General Public License v2 or later

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui import theme
from plugins.login.setup_steps import build_steps
from utils import settings
from utils.functions import get_resource_path
from utils.logger import logger

_BLUE = "#1E6FD9"
_BLUE_HOVER = "#0A4275"
_GREEN = "#1E8E3E"
_GREEN_HOVER = "#177B33"
_POLL_MS = 2000


def _c(light, dark):
    """Pick a colour for the active appearance mode."""
    try:
        return dark if theme.is_dark() else light
    except Exception:  # noqa: BLE001
        return light


def _pill_button(text, fg, hover, width=400, height=46):
    btn = QPushButton(text)
    btn.setFixedSize(width, height)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setStyleSheet(
        f"QPushButton {{ background-color: {fg}; color: white; border: none;"
        f" border-radius: {height // 2}px; font-size: 16px;"
        f" font-weight: 700; }}"
        f"QPushButton:hover {{ background-color: {hover}; }}"
        f"QPushButton:disabled {{ background-color: #9AA7B5; }}"
    )
    return btn


def _link_button(text):
    btn = QPushButton(text)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setStyleSheet(
        f"QPushButton {{ background: transparent; border: none;"
        f" color: {_c(_BLUE, '#3a7ebf')}; font-size: 13px; }}"
        f"QPushButton:hover {{ text-decoration: underline; }}"
    )
    return btn


def _card() -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ background-color: {_c('#F5F5F5', '#1E1E1E')};"
        f" border: 1px solid {_c('#E0E0E0', '#333333')};"
        f" border-radius: 12px; }}"
        f"QLabel {{ border: none; background: transparent; }}"
    )
    lay = QVBoxLayout(card)
    lay.setContentsMargins(18, 14, 18, 14)
    lay.setSpacing(8)
    return card, lay


class SetupWizardScreen:
    """Full-window wizard shown once, right after first sign-in."""

    def __init__(self, app, on_complete_callback):
        self.app = app
        self.on_complete = on_complete_callback
        self.frame = None
        self.steps = build_steps(app)
        self.index = -1                 # current step (-1 = welcome)
        self._poll_id = None
        self._active = False            # a step's work is running / polling
        self._act_seq = 0               # bumped each activation; stale worker
        #                                 on_status callbacks are ignored
        self.results = {}               # step.key -> "done" | "skipped"

    # ── Lifecycle ───────────────────────────────────────────────────

    def show(self):
        if not self.steps:
            # Nothing to set up on this platform — go straight through.
            logger.info("[SETUP] No applicable steps; finishing wizard.")
            self._finish()
            return
        self._build_welcome()

    def destroy(self):
        self._cancel_poll()
        # The central widget is owned/replaced by the QMainWindow; nothing to
        # tear down manually — just drop our reference.
        self.frame = None

    # ── Welcome ─────────────────────────────────────────────────────

    def _build_welcome(self):
        col = self._new_container()
        self._add_shield(col)

        col.addWidget(self._title_label(
            "Let's finish setting up Phoenix", 22))
        col.addSpacing(8)
        col.addWidget(self._muted_label(
            "We'll turn on your protection in a few quick, guided steps.\n"
            "You can skip anything and set it up later.", 14, center=True))
        col.addSpacing(22)

        checklist, chk_lay = _card()
        for step in self.steps:
            done = self._safe(step.is_complete, False)
            chk_lay.addLayout(self._checklist_row(step, done))
        col.addWidget(checklist)
        col.addSpacing(24)

        start = _pill_button("Get Protected", _BLUE, _BLUE_HOVER)
        start.clicked.connect(self._start_flow)
        col.addWidget(start, 0, Qt.AlignmentFlag.AlignHCenter)
        col.addSpacing(10)

        skip = _link_button("Skip for now")
        skip.clicked.connect(self._skip_all)
        col.addWidget(skip, 0, Qt.AlignmentFlag.AlignHCenter)
        col.addStretch(1)

    def _checklist_row(self, step, done):
        row = QHBoxLayout()
        row.setSpacing(12)

        icon = QLabel(step.icon)
        icon.setStyleSheet("font-size: 20px;")
        icon.setFixedWidth(32)
        row.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        title = QLabel(step.title)
        title.setStyleSheet(
            f"font-size: 14px; font-weight: 700;"
            f" color: {_c('#333333', '#EEEEEE')};")
        sub = QLabel(step.subtitle)
        sub.setStyleSheet(
            f"font-size: 12px; color: {_c('#777777', '#999999')};")
        text_col.addWidget(title)
        text_col.addWidget(sub)
        row.addLayout(text_col, 1)

        state = QLabel("✓ Ready" if done else "•")
        state.setStyleSheet(
            f"font-size: 12px;"
            f" font-weight: {'700' if done else '400'};"
            f" color: {_c(_GREEN, '#2CC985') if done else _c('#BBBBBB', '#666666')};")
        row.addWidget(state)
        return row

    # ── Flow control ────────────────────────────────────────────────

    def _start_flow(self):
        self.index = -1
        self._advance()

    def _advance(self):
        """Move to the next step that is both applicable and not yet complete."""
        self._cancel_poll()
        self._active = False
        # Signal the step we're leaving so any worker thread it left running
        # stops (and its stale on_status callbacks are already ignored via the
        # activation sequence guard).
        if 0 <= self.index < len(self.steps):
            self.steps[self.index]._cancel.set()
        self._act_seq += 1
        self.index += 1
        while self.index < len(self.steps):
            step = self.steps[self.index]
            if self._safe(step.is_complete, False):
                logger.info(
                    f"[SETUP] step '{step.key}' already complete — skipping")
                self.results.setdefault(step.key, "done")
                self.index += 1
                continue
            logger.info(
                f"[SETUP] showing step {self.index + 1}/{len(self.steps)}: "
                f"'{step.key}'")
            self._build_step(step)
            return
        logger.info(f"[SETUP] all steps handled; results={self.results}")
        self._build_success()

    # ── Step screen ─────────────────────────────────────────────────

    def _build_step(self, step):
        col = self._new_container()

        # Progress indicator (Step X of N + dots)
        step_no = QLabel(f"Step {self.index + 1} of {len(self.steps)}")
        step_no.setStyleSheet(
            f"font-size: 12px; font-weight: 700;"
            f" color: {_c('#999999', '#888888')};")
        step_no.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        col.addWidget(step_no)
        col.addSpacing(8)

        dots = QHBoxLayout()
        dots.addStretch(1)
        for i in range(len(self.steps)):
            done = i < self.index or self.results.get(self.steps[i].key)
            if i == self.index:
                color = _c(_BLUE, "#3a7ebf")
            elif done:
                color = _c(_GREEN, "#2CC985")
            else:
                color = _c("#DDDDDD", "#444444")
            dot = QFrame()
            dot.setFixedSize(22, 6)
            dot.setStyleSheet(
                f"background-color: {color}; border-radius: 3px;")
            dots.addWidget(dot)
            dots.addSpacing(6)
        dots.addStretch(1)
        col.addLayout(dots)
        col.addSpacing(18)

        icon = QLabel(step.icon)
        icon.setStyleSheet("font-size: 46px;")
        icon.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        col.addWidget(icon)
        col.addSpacing(6)

        col.addWidget(self._title_label(step.title, 20))
        col.addSpacing(8)
        col.addWidget(self._muted_label(step.detail, 14, center=True))
        col.addSpacing(18)

        # Instructions card (optional)
        if getattr(step, "instructions", None):
            col.addWidget(self._instructions_card(step.instructions))
            col.addSpacing(16)

        # Progress bar (hidden until work starts)
        self._bar = QProgressBar()
        self._bar.setRange(0, 0)  # indeterminate
        self._bar.setFixedWidth(400)
        self._bar.setTextVisible(False)
        col.addWidget(self._bar, 0, Qt.AlignmentFlag.AlignHCenter)
        self._bar.hide()
        col.addSpacing(6)

        # Status line
        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._status.setStyleSheet("font-size: 12px; color: #888888;")
        col.addWidget(self._status)
        col.addSpacing(14)

        # Primary action
        self._primary = _pill_button(step.primary_label, _BLUE, _BLUE_HOVER)
        self._primary.clicked.connect(self._on_primary)
        col.addWidget(self._primary, 0, Qt.AlignmentFlag.AlignHCenter)
        col.addSpacing(10)

        # Skip this step
        self._skip_btn = _link_button("Skip this step")
        self._skip_btn.clicked.connect(self._skip_step)
        col.addWidget(self._skip_btn, 0, Qt.AlignmentFlag.AlignHCenter)
        col.addStretch(1)

    def _instructions_card(self, instructions) -> QFrame:
        card, lay = _card()
        for i, text in enumerate(instructions):
            line = QHBoxLayout()
            line.setSpacing(12)
            num = QLabel(str(i + 1))
            num.setFixedSize(26, 26)
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num.setStyleSheet(
                f"background-color: {_BLUE}; color: #FFFFFF;"
                f" border-radius: 13px; font-size: 12px; font-weight: 700;")
            line.addWidget(num, 0, Qt.AlignmentFlag.AlignTop)
            lbl = QLabel(str(text))
            lbl.setWordWrap(True)
            lbl.setStyleSheet(
                f"font-size: 13px; color: {_c('#444444', '#CCCCCC')};")
            line.addWidget(lbl, 1)
            lay.addLayout(line)
        return card

    # ── Step actions ────────────────────────────────────────────────

    def _on_primary(self):
        if self._active:
            return
        step = self.steps[self.index]
        logger.info(f"[SETUP] primary clicked for step '{step.key}' — begin()")
        self._active = True
        step._failed = None
        step._cancel.clear()
        self._act_seq += 1
        my_seq = self._act_seq
        self._primary.setEnabled(False)
        self._primary.setText(step.working_label)
        self._skip_btn.setText("Skip this step")
        self._bar.show()
        self._set_status(step.working_label)

        # on_status is called from worker threads — marshal to the UI thread,
        # but ignore updates from a superseded activation so a left-behind
        # worker (e.g. the antivirus approval loop) can't write into a later
        # step's screen.
        def on_status(text, _seq=my_seq):
            if _seq != self._act_seq:
                return
            try:
                self.app.after(0, self._set_status, text)
            except Exception:  # noqa: BLE001
                pass

        try:
            step.begin(on_status)
        except Exception as e:  # noqa: BLE001
            logger.error(f"[SETUP] begin() failed for {step.key}: {e}")
            step._failed = "Something went wrong. You can try again or skip."
        self._schedule_poll()

    def _schedule_poll(self):
        self._cancel_poll()
        self._poll_id = self.app.after(_POLL_MS, self._poll)

    def _poll(self):
        if self.frame is None or self.index >= len(self.steps):
            return
        step = self.steps[self.index]

        if self._safe(step.is_complete, False):
            logger.info(f"[SETUP] step '{step.key}' reported complete")
            self.results[step.key] = "done"
            self._on_step_done()
            return

        failure = self._safe(step.check_failed, None)
        if failure:
            logger.error(f"[SETUP] step '{step.key}' failed: {failure}")
            self._show_failure(failure)
            return

        self._schedule_poll()

    def _on_step_done(self):
        self._cancel_poll()
        self._active = False
        try:
            self._bar.hide()
            self._set_status("✓ Done")
        except Exception:  # noqa: BLE001
            pass
        # Brief beat so the checkmark registers, then advance.
        self.app.after(600, self._advance)

    def _show_failure(self, message):
        self._cancel_poll()
        self._active = False
        try:
            self._bar.hide()
            self._status.setText(message)
            self._status.setStyleSheet(
                f"font-size: 12px; color: {_c('#C0392B', '#E74C3C')};")
            self._primary.setEnabled(True)
            self._primary.setText("Try Again")
            self._skip_btn.setText("Skip this step")
        except RuntimeError:  # widgets from a replaced screen
            pass

    def _skip_step(self):
        if self.index < len(self.steps):
            self.results[self.steps[self.index].key] = "skipped"
        self._advance()

    # ── Success ─────────────────────────────────────────────────────

    def _build_success(self):
        col = self._new_container()
        self._add_shield(col)

        any_done = any(v == "done" for v in self.results.values())
        title = QLabel("You're protected!" if any_done else "Setup complete")
        title.setStyleSheet(
            f"font-size: 24px; font-weight: 700;"
            f" color: {_c(_GREEN, '#2CC985')};")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        col.addWidget(title)
        col.addSpacing(8)

        col.addWidget(self._muted_label(
            "Here's what's set up on your device.", 14, center=True))
        col.addSpacing(20)

        summary, sum_lay = _card()
        for step in self.steps:
            done = self.results.get(step.key) == "done" or self._safe(
                step.is_complete, False)
            line = QHBoxLayout()
            line.setSpacing(12)
            icon = QLabel(step.icon)
            icon.setStyleSheet("font-size: 18px;")
            icon.setFixedWidth(30)
            line.addWidget(icon)
            lbl = QLabel(step.title)
            lbl.setStyleSheet(
                f"font-size: 13px; font-weight: 700;"
                f" color: {_c('#333333', '#EEEEEE')};")
            line.addWidget(lbl, 1)
            state = QLabel("✓ Enabled" if done else "Skipped")
            state.setStyleSheet(
                f"font-size: 12px;"
                f" font-weight: {'700' if done else '400'};"
                f" color: {_c(_GREEN, '#2CC985') if done else _c('#999999', '#888888')};")
            line.addWidget(state)
            sum_lay.addLayout(line)
        col.addWidget(summary)
        col.addSpacing(24)

        go = _pill_button("Go to Dashboard", _GREEN, _GREEN_HOVER)
        go.clicked.connect(self._finish)
        col.addWidget(go, 0, Qt.AlignmentFlag.AlignHCenter)
        col.addStretch(1)

    # ── Completion ──────────────────────────────────────────────────

    def _skip_all(self):
        logger.info("[SETUP] User skipped setup wizard")
        self._finish()

    def _finish(self):
        settings.set("setup", "complete", True)
        settings.set("auth", "logged_in", True)
        # Keep the legacy flag satisfied so the old VPN-only onboarding branch
        # never re-triggers.
        settings.set("vpn", "onboarding_complete", True)
        logger.info("[SETUP] Setup wizard complete")
        self.destroy()
        if self.on_complete:
            self.on_complete()

    # ── UI helpers ──────────────────────────────────────────────────

    def _set_status(self, text):
        try:
            self._status.setText(text)
            self._status.setStyleSheet("font-size: 12px; color: #888888;")
        except (RuntimeError, AttributeError):
            pass  # screen replaced under a stale callback

    def _cancel_poll(self):
        if self._poll_id:
            try:
                self.app.after_cancel(self._poll_id)
            except Exception:  # noqa: BLE001
                pass
            self._poll_id = None

    def _new_container(self) -> QVBoxLayout:
        """Replace the central widget with a fresh centered column."""
        page = QWidget()
        outer = QHBoxLayout(page)
        outer.addStretch(1)
        column = QWidget()
        column.setMaximumWidth(520)
        col = QVBoxLayout(column)
        col.setContentsMargins(20, 40, 20, 20)
        col.setSpacing(0)
        outer.addWidget(column)
        outer.addStretch(1)
        self.frame = page
        self.app.setCentralWidget(page)
        return col

    def _add_shield(self, col: QVBoxLayout, size=96):
        try:
            from gui.qt_widgets import pixmap
            path = get_resource_path(
                os.path.join("resources", "icons", "PhoenixMark.png"))
            pm = pixmap(path, size)
            if not pm.isNull():
                shield = QLabel()
                shield.setPixmap(pm)
                shield.setAlignment(Qt.AlignmentFlag.AlignHCenter)
                col.addWidget(shield)
                col.addSpacing(20)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[SETUP] Shield logo load failed: {e}")

    def _title_label(self, text, size):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"font-size: {size}px; font-weight: 700;"
            f" color: {_c('#333333', '#FFFFFF')};")
        lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        lbl.setWordWrap(True)
        return lbl

    def _muted_label(self, text, size, center=False):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"font-size: {size}px; color: {_c('#666666', '#AAAAAA')};")
        if center:
            lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        lbl.setWordWrap(True)
        return lbl

    @staticmethod
    def _safe(fn, default):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[SETUP] check failed: {e}")
            return default
