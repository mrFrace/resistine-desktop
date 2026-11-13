## @file main.py
## @namespace plugins.alerts
"""Alerts plugin (PyQt6): the SIEM alerts siemgent sends about the user's
machines, newest first, each with its findings, its text and Ask AI.

The alerts arrive over Matrix into plugins/chat/siem_alerts.py; this screen
only reads that store (plugins/dashboard/alerts.py turns each message into a
title, severity and findings). It also sends the desktop notification for a
new high or critical alert, whose click opens that alert here.

Author: Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

from __future__ import annotations

import os
import threading
import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextBrowser,
    QWidget,
)

from gui import theme
from gui.page_kit import MenuRow, Page, PageHeader, RowList, SlideStack, back_link, line_icon, muted
from gui.qt_widgets import set_pill
from plugins.base_plugin import BasePlugin
from plugins.dashboard import alerts as recent_alerts
from plugins.dashboard import digest
from utils.logger import logger

_DIR = os.path.dirname(os.path.realpath(__file__))
_STARTED_AT = time.time()
_NOTIFIED: set = set()
_notified_lock = threading.Lock()

_SEV_PILL = {"critical": "error", "high": "error", "medium": "warning", "unknown": "warning",
             "low": "info", "info": "ok"}
_KIND_ICON = {"triage": "activity", "hunt": "folder-search", "result": "shield-check"}


def _store():
    from plugins.chat import siem_alerts
    return siem_alerts.store()


def pill(info: dict) -> tuple:
    """(kind, text) of an alert's status pill: the verdict of a hunt result,
    otherwise the severity."""
    if info["kind"] == "result" and info["verdict"]:
        v = info["verdict"].lower()
        return ("ok" if "false" in v else "error" if "true" in v else "warning"), info["verdict"]
    return _SEV_PILL[info["severity"]], info["severity"].capitalize()


class _AlertText(QTextBrowser):
    """An alert's text as rich text, as tall as its content (the page
    scrolls, not this). Raw HTML in the alert is escaped and links never
    open: the text quotes the monitored system and is not ours."""

    def __init__(self, md: str):
        super().__init__()
        from plugins.chat.qt_markdown import markdown_to_html, stylesheet

        self.setObjectName("Transparent")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        # padding: 0 overrides the app-wide QTextEdit padding (7px 10px), which
        # took the space the height below makes for the text (as in chat).
        self.setStyleSheet("QTextBrowser { background: transparent; border: none; padding: 0; }")
        self.document().setDocumentMargin(0)
        self.document().setDefaultStyleSheet(
            stylesheet(theme.color("text_primary")) + "pre { white-space: pre-wrap; }")
        self.setHtml(markdown_to_html(md, allow_html=False))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        # Refit whenever the text lays out again, not only on a resize.
        self.document().documentLayout().documentSizeChanged.connect(lambda _s: self._fit())

    def _fit(self) -> None:
        width = self.viewport().width()
        if width <= 0:
            return
        if self.document().textWidth() != width:
            self.document().setTextWidth(width)
        chrome = self.height() - self.viewport().height()  # frame, padding, margins
        h = int(self.document().size().height()) + 4 + max(0, chrome)
        if h != self.height():
            self.setFixedHeight(h)

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self._fit()

    def showEvent(self, e):  # noqa: N802
        super().showEvent(e)
        self._fit()


class Plugin(BasePlugin):
    def __init__(self, app):
        super().__init__(
            id="013", version="2026.10.23", order=1.5, name="Alerts",
            status=None,
            description="Security alerts about your machines from the Phoenix SIEM.",
            supported_systems=["Windows", "Linux", "Mac"],
            translations={"US": "Alerts", "ES": "Alertas", "FR": "Alertes"},
            icon_light_path=os.path.join(_DIR, "alerts_light.png"),
            icon_dark_path=os.path.join(_DIR, "alerts_dark.png"),
            uninstall_enabled=False,
        )
        self.app = app
        self._views: SlideStack | None = None
        self._list = None          # (RowList, PageHeader) of the list page
        self._detail = None        # the open alert's page widget
        self._day = None           # a digest day's page widget, under the alert's
        self._subscribed = False
        self._subscribe()  # notify even before the screen is opened

    # ---- status: the nav icon glows while there are unread alerts ----------
    def check_status(self):
        try:
            return "warning" if _store().unread else None
        except Exception:  # noqa: BLE001
            return None

    # ---- screen -------------------------------------------------------------
    def create_main_screen(self):
        page = Page()
        header = PageHeader("Alerts")
        page.add(header)
        rows = RowList()
        page.spacing(18)
        page.add(rows)
        page.spacing(14)
        page.add(muted("Alerts come from Phoenix's SIEM about the machines you own. "
                       "Triage sums up a batch of alerts, Investigating means a hunt "
                       "started, and the hunt result says whether it was a real threat."))
        page.stretch()
        self._views = SlideStack(fit_height=False)
        self._views.addWidget(page.widget)
        self._list = (rows, header)
        self._detail = None
        self._day = None
        self._fill()
        return self._views

    def on_screen_shown(self):
        # The sidebar's Alerts button opens the list, not an alert left open
        # (show() opens one after this when a notification asked for it).
        self._close_detail(animate=False)
        self._close_day(animate=False)
        self._fill()

    def repaint(self) -> None:
        """Rebuild the list (Settings calls it when the digest is switched)."""
        self._close_detail(animate=False)
        self._close_day(animate=False)
        self._fill()

    def _visible(self) -> bool:
        try:
            return self._views is not None and self._views.isVisible()
        except RuntimeError:  # deleted by a rebuild
            self._views = None
            return False

    def _fill(self) -> None:
        if self._list is None:
            return
        rows, header = self._list
        try:
            rows.clear()
        except RuntimeError:  # page deleted by a rebuild
            self._list = None
            return
        st = _store()
        alerts = recent_alerts.newest_first(st.all())
        folded = digest.enabled()
        subtitle = (f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}, newest first"
                    if alerts else "No alerts yet. Alerts about machines you own appear here.")
        if folded and alerts:
            subtitle += " · " + digest._t("subtitle")
        header.set_subtitle(subtitle)
        if folded:
            # The digest folds a day's quieter alerts into one row; high and
            # critical ones stay on their own. The store is untouched.
            for entry in digest.fold(alerts):
                rows.add_row(self._row(entry["alert"]) if entry["kind"] == "alert"
                             else self._day_row(entry))
        else:
            for a in alerts:
                rows.add_row(self._row(a))
        if st.unread and self._visible():
            st.mark_read()
            self._repaint_elsewhere()

    def _row(self, alert: dict) -> QWidget:
        info = recent_alerts.parse(alert.get("body", ""))
        hint = " · ".join(p for p in (info["host"], recent_alerts.ago(alert.get("ts"))) if p)
        row = MenuRow(_KIND_ICON.get(info["kind"], "info"), info["title"], hint,
                      on_click=lambda e=alert.get("event_id"): self.open_alert(e))
        row._title.setWordWrap(True)  # long file paths
        row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        label = QLabel()
        set_pill(label, *pill(info))
        row.layout().insertWidget(2, label, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _day_row(self, entry: dict) -> QWidget:
        row = MenuRow("archive", digest.title(entry), digest.hint(entry),
                      on_click=lambda d=entry["day"]: self.open_day(d))
        row._hint.setTextFormat(Qt.TextFormat.PlainText)  # host names are server text
        row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        return row

    # ---- one digest day -------------------------------------------------------
    def open_day(self, day) -> None:
        """A folded day's alerts, one by one (every severity, newest first)."""
        if self._views is None:
            return
        entry = next((e for e in digest.fold(_store().all())
                      if e["kind"] == "day" and e["day"] == day), None)
        if entry is None:
            return
        self._close_detail(animate=False)
        self._close_day(animate=False)
        page = Page()
        page.add(back_link("Alerts", self._close_day))
        n = len(entry["alerts"])
        page.add(PageHeader(digest.day_label(entry["day"]),
                            f"{n} alert{'s' if n != 1 else ''} · " + digest.hint(entry)))
        page.spacing(18)
        rows = RowList()
        for a in recent_alerts.newest_first(entry["alerts"]):
            rows.add_row(self._row(a))
        page.add(rows)
        page.stretch()
        self._views.addWidget(page.widget)
        self._day = page.widget
        self._views.push(page.widget)

    def _close_day(self, animate: bool = True) -> None:
        if self._detail is not None:
            self._close_detail(animate=False)
        page, self._day = self._day, None
        if page is None or self._views is None:
            return
        if animate:
            self._views.back()
            QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                              if self._views is not None else None)
        else:
            self._views.home()
            self._views.removeWidget(page)
            page.deleteLater()

    # ---- one alert ------------------------------------------------------------
    def open_alert(self, event_id: str) -> None:
        """One alert, in full: what it is about, its findings and the text."""
        alert = next((a for a in _store().all() if a.get("event_id") == event_id), None)
        if alert is None or self._views is None:
            return
        self._close_detail(animate=False)
        body = alert.get("body", "")
        info = recent_alerts.parse(body)
        page = Page()
        page.add(back_link("Alerts", self._close_detail))
        header = PageHeader(info["title"], recent_alerts.subtitle(info, alert.get("ts")),
                            status=pill(info))
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.wrap_title()
        header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        ask = QPushButton("Ask AI")
        ask.setIcon(QIcon(line_icon("message-circle", "#ffffff", 18)))
        ask.setCursor(Qt.CursorShape.PointingHandCursor)
        ask.setToolTip("Start a chat with Phoenix AI about this alert")
        ask.clicked.connect(lambda: self._ask_ai(body, alert.get("ts")))
        header.add_control(ask)
        page.add(header)
        if info["findings"]:
            page.section("Findings")
            found = RowList()
            for f in info["findings"]:
                found.add_row(self._finding_row(f))
            page.add(found)
        page.section("Details")
        page.spacing(6)
        page.add(_AlertText(recent_alerts.detail_text(body) or body))
        page.stretch()
        self._views.addWidget(page.widget)
        self._detail = page.widget
        self._views.push(page.widget)

    def _close_detail(self, animate: bool = True) -> None:
        page, self._detail = self._detail, None
        if page is None or self._views is None:
            return
        if animate:
            self._views.back(self._day)  # to the digest day when one is open
            QTimer.singleShot(400, lambda: (self._views.removeWidget(page), page.deleteLater())
                              if self._views is not None else None)
        elif self._day is not None:
            self._views.setCurrentWidget(self._day)
            self._views.removeWidget(page)
            page.deleteLater()
        else:
            self._views.home()
            self._views.removeWidget(page)
            page.deleteLater()

    @staticmethod
    def _finding_row(finding: dict) -> QWidget:
        row = QWidget()
        row.setObjectName("Transparent")
        h = QHBoxLayout(row)
        h.setContentsMargins(4, 8, 4, 8)
        h.setSpacing(14)
        name = QLabel(finding["name"])
        name.setObjectName("RowTitle")
        name.setTextFormat(Qt.TextFormat.PlainText)
        name.setWordWrap(True)
        h.addWidget(name, 1)
        label = QLabel()
        set_pill(label, _SEV_PILL[finding["severity"]], finding["severity"].capitalize())
        h.addWidget(label, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def _ask_ai(self, body: str, ts=None) -> None:
        chat = next((p for p in getattr(self.app, "plugins", []) if p.get_name() == "Chat"), None)
        if chat is None or getattr(chat, "client", None) is None:
            self.app.show_notification(
                "Phoenix AI isn't set up yet. Choose an AI in Settings first.", type="warning")
            return
        self.app.select_frame_by_name("frame_Chat")

        def go():
            try:
                if not chat.ask_about_alert(body, ts):
                    self.app.show_notification("The chat isn't ready yet. Try again.", type="warning")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Alerts: Ask AI failed: {e}")
        QTimer.singleShot(0, go)

    # ---- show an alert from elsewhere (notification, Dashboard panel) --------
    def show(self, event_id: str | None = None) -> None:
        """Go to the Alerts screen, on one alert when *event_id* is given."""
        try:
            self.app.navigate(self.get_name())
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Could not open Alerts: {e}")
            return
        if event_id:
            self.open_alert(event_id)

    # ---- new alerts -------------------------------------------------------------
    def _subscribe(self) -> None:
        if self._subscribed:
            return
        try:
            from plugins.chat import siem_alerts
            siem_alerts.subscribe(self._arrived)
            self._subscribed = True
        except Exception:  # noqa: BLE001
            pass

    def _arrived(self, alert: dict) -> None:
        # Matrix thread: repaint on the Qt thread.
        try:
            self.app.after(0, self._fill)
        except Exception:  # noqa: BLE001
            pass
        self._notify(alert)

    def _repaint_elsewhere(self) -> None:
        """The Dashboard's panel shows the unread count: refresh it."""
        dash = next((p for p in getattr(self.app, "plugins", []) if p.get_name() == "Dashboard"), None)
        repaint = getattr(dash, "repaint_alerts", None)
        if repaint is not None:
            try:
                repaint()
            except Exception:  # noqa: BLE001
                pass

    def _notify(self, alert: dict) -> None:
        """A desktop notification for a new high or critical alert."""
        from utils import settings as app_settings

        if not app_settings.get("dashboard", "alert_notifications", True):
            return
        note = recent_alerts.notification(alert, _STARTED_AT)
        with _notified_lock:
            if note is None or note["event_id"] in _NOTIFIED:
                return
            _NOTIFIED.add(note["event_id"])
        eid = note["event_id"]
        try:
            from utils import notifications
            notifications.send(note["title"], note["body"], urgency=note["urgency"],
                               on_click=(lambda: self.app.after(0, self._raise_on, eid))
                               if eid else None)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Alert notification failed: {e}")

    def _raise_on(self, event_id: str) -> None:
        """Clicked notification: bring the window up on that alert."""
        try:
            win = self.app
            win.showNormal()
            win.raise_()
            win.activateWindow()
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Could not raise the window for an alert: {e}")
        self.show(event_id)

    def destroy(self) -> None:
        if self._subscribed:
            try:
                from plugins.chat import siem_alerts
                siem_alerts.unsubscribe(self._arrived)
            except Exception:  # noqa: BLE001
                pass
            self._subscribed = False
