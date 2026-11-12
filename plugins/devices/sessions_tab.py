"""Devices page: the Sessions tab (every device signed in to the account).

One row per device from ``GET /v1/devices`` (plugins/devices/sessions_api.py):
this device first, then the other Phoenix installs, the other Matrix apps
(Element, Element X…) and the installs that are no longer signed in but
still hold a VPN peer or an agent. Each row shows whether the device is
cross-signed, checked here from the account's keys
(plugins/login/cross_signing.py).

A row opens a page that names exactly what removing it does; removal runs
on the server (session, VPN peer and agent together). This device is never
removable here (that is Sign out), and is the only one the app verifies:
with the recovery key, on a page that slides in like the rest.

Fleet-wide: the device selector does not apply. Server strings are plain
text everywhere.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

from gui.page_kit import KVList, MenuRow, Page, PageHeader, RowList, back_link, muted, section_heading
from plugins.devices import sessions_api
from plugins.devices.api import NOT_AVAILABLE
from plugins.login import cross_signing as cs
from utils.logger import logger

REFETCH_AFTER_S = 60
RECENT_S = 7 * 86400  # removing a session used this recently gets a warning
_OS_HINTS = (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"),
             ("Windows", "Windows"), ("Mac OS", "macOS"), ("Macintosh", "macOS"),
             ("Linux", "Linux"))


def _plain(lbl: QLabel) -> QLabel:
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    return lbl


def _plain_row(row: MenuRow) -> MenuRow:
    """MenuRow labels default to auto-detected rich text: server strings
    must not render as HTML."""
    row._title.setTextFormat(Qt.TextFormat.PlainText)
    row._hint.setTextFormat(Qt.TextFormat.PlainText)
    return row


def _parse_ts(value: str):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def seconds_since(value: str, now: float | None = None):
    dt = _parse_ts(value) if value else None
    if dt is None:
        return None
    return max(0.0, (now if now is not None else time.time()) - dt.timestamp())


def os_of(user_agent: str) -> str:
    for needle, name in _OS_HINTS:
        if needle in (user_agent or ""):
            return name
    return ""


def group(rows: list) -> dict:
    """{"this", "phoenix", "apps", "gone"} -> rows, in the server's order."""
    out = {"this": [], "phoenix": [], "apps": [], "gone": []}
    for r in rows:
        if r.current:
            out["this"].append(r)
        elif not r.signed_in:
            out["gone"].append(r)
        elif r.phoenix:
            out["phoenix"].append(r)
        else:
            out["apps"].append(r)
    return out


class SessionsTab:
    def __init__(self, ctx):
        self.ctx = ctx
        self.t = lambda key, **kw: ctx.t(f"sessions_{key}", **kw)
        self.widget = QWidget()
        self.widget.setObjectName("Transparent")
        self._col = QVBoxLayout(self.widget)
        self._col.setContentsMargins(0, 20, 0, 32)
        self._col.setSpacing(0)
        self._rows = None          # list[DeviceRow] once loaded
        self._status = {}          # device_id -> cross-signing status
        self._error = None
        self._loading = False
        self._loaded_at = 0.0
        self._render()
        self._fetch()

    # ---- data ---------------------------------------------------------------

    def set_scope(self) -> None:
        """Fleet-wide: the device selector changes nothing here."""

    def refresh(self) -> None:
        if time.monotonic() - self._loaded_at > REFETCH_AFTER_S:
            self._fetch()

    def _fetch(self) -> None:
        if self._loading:
            return
        self._loading = True

        def work():
            rows, error = sessions_api.list_devices()
            status = {}
            if rows:
                try:
                    own = cs.query_own_keys()
                    status = {r.device_id: cs.device_status(own, r.device_id) for r in rows}
                except cs.VerificationError as e:
                    logger.info(f"[DEVICES] cross-signing status unavailable: {e}")
            self.ctx.app.after(0, lambda: self._loaded(rows, error, status))

        threading.Thread(target=work, daemon=True, name="devices-sessions").start()

    def _loaded(self, rows, error, status) -> None:
        self._loading = False
        self._loaded_at = time.monotonic()
        self._error = error
        if rows is not None:
            self._rows, self._status = rows, status
        try:
            self._render()
        except RuntimeError:  # the page was torn down meanwhile
            pass

    # ---- list ---------------------------------------------------------------

    def _clear(self) -> None:
        while self._col.count():
            item = self._col.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()  # deleteLater waits for the event loop: don't paint it meanwhile
                w.deleteLater()

    def _render(self) -> None:
        self._clear()
        col = self._col
        if self._rows is None:
            if self._error == NOT_AVAILABLE:
                text = self.t("not_available")
            elif self._error:
                text = self.t("error", error=self._error)
            else:
                text = self.t("loading")
            col.addWidget(_plain(muted(text)))
            col.addStretch(1)
            return
        if self._error:
            col.addWidget(_plain(muted(self.t("stale", error=self._error))))
            col.addSpacing(12)
        groups = group(self._rows)
        stale = sessions_api.stale_installs(self._rows, socket.gethostname())
        first = True
        for key in ("this", "phoenix", "apps", "gone"):
            if not groups[key]:
                continue
            if not first:
                col.addSpacing(28)
            first = False
            col.addWidget(section_heading(self.t(f"group_{key}")))
            col.addSpacing(10)
            lst = RowList()
            for r in groups[key]:
                lst.add_row(self._row(r))
                if r.current and self._status.get(r.device_id) == cs.UNVERIFIED:
                    lst.add_row(MenuRow("key", self.t("verify"), self.t("verify_hint"),
                                        on_click=self._open_verify))
            if key == "this" and stale:
                lst.add_row(_plain_row(MenuRow(
                    "trash", self.t("stale_row"),
                    self.t("stale_hint", names=", ".join(r.device_id for r in stale)),
                    on_click=lambda _s=stale: self._open_stale(_s))))
            col.addWidget(lst)
            if key == "this" and self._status.get(groups[key][0].device_id) == cs.NO_CROSS_SIGNING:
                col.addSpacing(8)
                col.addWidget(_plain(muted(self.t("no_cross_signing"))))
        col.addSpacing(28)
        col.addWidget(section_heading(self.t("group_more")))
        col.addSpacing(10)
        more = RowList()
        more.add_row(MenuRow("external-link", self.t("manage_browser"),
                             self.t("manage_browser_hint"), on_click=self._open_account))
        col.addWidget(more)
        col.addSpacing(16)
        col.addWidget(_plain(muted(self.t("caveat"))))
        col.addStretch(1)

    def name(self, r) -> str:
        if r.vpn and r.vpn.hostname:
            return r.vpn.hostname
        if r.agent and r.agent.agent_name:
            return r.agent.agent_name
        s = r.session
        if s:
            product = s.client_name or self.t("unknown_app")
            os_name = os_of(s.user_agent)
            return f"{product} · {os_name}" if os_name else product
        return r.device_id

    def _status_text(self, r) -> str:
        return {
            cs.VERIFIED: self.t("verified"),
            cs.UNVERIFIED: self.t("not_verified"),
        }.get(self._status.get(r.device_id), "")

    def ago(self, value: str) -> str:
        secs = seconds_since(value)
        if secs is None:
            return ""
        if secs < 90:
            return self.t("ago_now")
        if secs < 3600:
            return self.t("ago_min", n=int(secs // 60))
        if secs < 86400:
            return self.t("ago_hours", n=int(secs // 3600))
        return self.t("ago_days", n=int(secs // 86400))

    def hint(self, r) -> str:
        bits = [r.device_id, self._status_text(r)]
        if r.session:
            seen = self.ago(r.session.last_active_at)
            bits.append(self.t("last_active", when=seen) if seen else "")
        if r.vpn and r.vpn.address:
            bits.append(self.t("vpn", address=r.vpn.address))
        if r.agent and r.agent.agent_id:
            bits.append(self.t("agent", id=r.agent.agent_id))
        return " · ".join(b for b in bits if b)

    def _row(self, r) -> MenuRow:
        icon = "monitor" if r.phoenix else ("archive" if not r.signed_in else "message-circle")
        if r.current:
            row = _plain_row(MenuRow(icon, self.t("this_device", name=self.name(r)),
                                     self.hint(r), chevron=False))
            row.setCursor(Qt.CursorShape.ArrowCursor)  # not clickable: Sign out is in Settings
            return row
        return _plain_row(MenuRow(icon, self.name(r), self.hint(r),
                                  on_click=lambda _r=r: self._open_device(_r)))

    def _open_account(self) -> None:
        def work():
            from plugins.login import oidc

            url = oidc.account_url()
            self.ctx.app.after(0, lambda: QDesktopServices.openUrl(QUrl(url)))

        threading.Thread(target=work, daemon=True, name="devices-account-url").start()

    # ---- device page (what removing it does) ---------------------------------

    def removal_text(self, r) -> str:
        """What Remove does to ``r``, in words the user can check."""
        name = self.name(r)
        if r.phoenix:
            parts = [self.t("remove_phx_session", name=name) if r.signed_in
                     else self.t("remove_phx_gone", name=name)]
            if r.vpn:
                parts.append(self.t("remove_phx_vpn", address=r.vpn.address or "?"))
            if r.agent:
                parts.append(self.t("remove_phx_agent_linked" if r.agent.linked
                                    else "remove_phx_agent", id=r.agent.agent_id or "?"))
            parts.append(self.t("remove_phx_after"))
            return " ".join(parts)
        return self.t("remove_app", name=name)

    def recent_warning(self, r, now: float | None = None) -> str:
        if r.phoenix or not r.session:
            return ""
        secs = seconds_since(r.session.last_active_at, now)
        if secs is None or secs > RECENT_S:
            return ""
        return self.t("remove_recent", when=self.ago(r.session.last_active_at), name=self.name(r))

    def _open_device(self, r) -> None:
        page = Page()
        page.add(back_link(self.ctx.t("title"), self.ctx.pop))
        header = PageHeader(self.name(r), r.device_id)
        header.title.setTextFormat(Qt.TextFormat.PlainText)
        header.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        page.add(header)

        page.section(self.t("section_details"))
        kv = KVList()
        status = self._status_text(r)
        if status:
            kv.add(self.t("key_verification"), status)
        if r.session:
            s = r.session
            if s.client_name:
                kv.add(self.t("key_app"), s.client_name)
            if s.user_agent:
                kv.add(self.t("key_user_agent"), s.user_agent)
            if s.last_active_at:
                kv.add(self.t("key_last_active"), self.ago(s.last_active_at))
            if s.last_active_ip:
                kv.add(self.t("key_ip"), s.last_active_ip)
            if s.created_at:
                created = _parse_ts(s.created_at)
                kv.add(self.t("key_created"), created.strftime("%Y-%m-%d %H:%M") if created
                       else s.created_at)
        else:
            kv.add(self.t("key_session"), self.t("not_signed_in"))
        if r.vpn:
            kv.add(self.t("key_vpn"), " · ".join(b for b in (r.vpn.hostname, r.vpn.address) if b))
        if r.agent:
            kv.add(self.t("key_agent"), " · ".join(b for b in (r.agent.agent_id, r.agent.agent_name) if b))
        for lbl in kv.findChildren(QLabel):
            lbl.setTextFormat(Qt.TextFormat.PlainText)
        page.add(kv)

        page.section(self.t("section_remove"))
        page.add(_plain(muted(self.removal_text(r))))
        warning = self.recent_warning(r)
        if warning:
            page.spacing(8)
            warn = _plain(muted(warning))
            warn.setObjectName("RowTitle")
            page.add(warn)
        page.spacing(10)
        result = _plain(muted(""))
        result.hide()
        lst = RowList()
        remove = MenuRow("trash", self.t("remove"), "", danger=True, chevron=False)
        remove.clicked.connect(lambda: self._remove(r, remove, result))
        lst.add_row(remove)
        page.add(lst)
        page.spacing(8)
        page.add(result)
        page.stretch()
        self.ctx.push(page.widget)

    def _remove(self, r, button: MenuRow, result: QLabel) -> None:
        button.setEnabled(False)
        result.setText(self.t("removing"))
        result.show()

        def work():
            ok, error = sessions_api.remove_device(r.device_id)
            self.ctx.app.after(0, lambda: self._removed(r, ok, error, button, result))

        threading.Thread(target=work, daemon=True, name="devices-remove").start()

    def _removed(self, r, ok, error, button, result) -> None:
        if ok or error == "gone":
            self._rows = [x for x in (self._rows or []) if x.device_id != r.device_id]
            self._render()
            self.ctx.pop()
            self._loaded_at = 0.0
            self._fetch()
            return
        try:
            button.setEnabled(True)
            result.setText(self.t("remove_failed", error=error or "?"))
        except RuntimeError:
            pass

    # ---- earlier installs of this computer ------------------------------------

    def _open_stale(self, rows) -> None:
        page = Page()
        page.add(back_link(self.ctx.t("title"), self.ctx.pop))
        page.add(PageHeader(self.t("stale_title"), self.t("stale_sub")))
        page.section(self.t("section_remove"))
        for r in rows:
            page.add(_plain(muted(f"{r.device_id}: {self.removal_text(r)}")))
            page.spacing(8)
        page.spacing(2)
        result = _plain(muted(""))
        result.hide()
        lst = RowList()
        remove = MenuRow("trash", self.t("stale_remove"), "", danger=True, chevron=False)
        remove.clicked.connect(lambda: self._remove_stale(rows, remove, result))
        lst.add_row(remove)
        page.add(lst)
        page.spacing(8)
        page.add(result)
        page.stretch()
        self.ctx.push(page.widget)

    def _remove_stale(self, rows, button: MenuRow, result: QLabel) -> None:
        button.setEnabled(False)
        result.setText(self.t("removing"))
        result.show()

        def work():
            failed = []
            for r in rows:
                ok, error = sessions_api.remove_device(r.device_id)
                if not ok and error != "gone":
                    failed.append(f"{r.device_id}: {error or '?'}")
            self.ctx.app.after(0, lambda: self._stale_removed(failed, button, result))

        threading.Thread(target=work, daemon=True, name="devices-remove-stale").start()

    def _stale_removed(self, failed, button, result) -> None:
        self._loaded_at = 0.0
        if not failed:
            self.ctx.pop()
            self._fetch()
            return
        self._fetch()
        try:
            button.setEnabled(True)
            result.setText(self.t("remove_failed", error="; ".join(failed)))
        except RuntimeError:
            pass

    # ---- verify this device ---------------------------------------------------

    def _open_verify(self) -> None:
        page = Page()
        page.add(back_link(self.ctx.t("title"), self.ctx.pop))
        page.add(PageHeader(self.t("verify"), self.t("verify_sub")))
        page.section(self.t("section_recovery_key"))
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setPlaceholderText(self.t("recovery_placeholder"))
        field.setMinimumHeight(36)
        page.add(field)
        page.spacing(8)
        page.add(_plain(muted(self.t("recovery_where"))))
        page.spacing(14)
        go = QPushButton(self.t("verify_button"))
        go.setCursor(Qt.CursorShape.PointingHandCursor)
        go.setFixedWidth(160)
        page.add(go, 0)
        page.spacing(10)
        result = _plain(muted(""))
        result.hide()
        page.add(result)
        page.stretch()

        def start():
            secret = field.text()
            field.clear()  # the recovery key lives only in this call from here on
            if not secret.strip():
                return
            go.setEnabled(False)
            field.setEnabled(False)
            result.setText(self.t("verifying"))
            result.show()

            def work(s=secret):
                code = None
                try:
                    cs.verify_this_device(s)
                except cs.VerificationError as e:
                    logger.warning(f"[DEVICES] verify this device: {e.code}")
                    code = e.code
                except Exception as e:  # noqa: BLE001
                    logger.error(f"[DEVICES] verify this device failed: {type(e).__name__}")
                    code = "unknown"
                self.ctx.app.after(0, lambda: done(code))

            threading.Thread(target=work, daemon=True, name="devices-verify").start()

        def done(code):
            try:
                go.setEnabled(True)
                field.setEnabled(True)
                if code is None:
                    result.setText(self.t("verify_done"))
                    self._loaded_at = 0.0
                    self._fetch()
                else:
                    result.setText(self.verify_error(code))
            except RuntimeError:
                pass

        go.clicked.connect(start)
        field.returnPressed.connect(start)
        self.ctx.push(page.widget)

    def verify_error(self, code: str) -> str:
        key = f"err_{code}" if re.fullmatch(r"[a-z_]{1,40}", code or "") else "err_unknown"
        try:
            return self.t(key)
        except KeyError:
            return self.t("err_unknown")
