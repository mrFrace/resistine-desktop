## @file win_console.py
## @namespace utils.win_console
"""Suppress flashing console windows from child processes on Windows.

Phoenix ships as a windowed (no-console) build. On Windows, any child
process started with the default flags briefly allocates its own console —
a black window that pops up and vanishes. The app shells out constantly
(WireGuard, ClamAV, Wazuh, `sc`, `icacls`, font probing, markdown
rendering, the updater…), so the user sees console windows flashing at
seemingly random times.

A handful of call sites already pass ``creationflags=CREATE_NO_WINDOW``,
but there are ~80 subprocess calls across the codebase and every new one is
a chance to regress. Instead of threading the flag through each call, inject
it once as the default at the ``subprocess.Popen`` layer — ``run``, ``call``,
``check_output`` and ``check_call`` all funnel through ``Popen``, so a single
patch covers them all. CREATE_NO_WINDOW only suppresses the *console*; GUI
child processes are unaffected, so this is safe to apply globally.
"""

import sys

CREATE_NO_WINDOW = 0x08000000


def suppress_child_console_windows() -> None:
    """Default every subprocess to CREATE_NO_WINDOW on Windows. Idempotent."""
    if not sys.platform.startswith("win"):
        return

    import subprocess

    if getattr(subprocess.Popen, "_resistine_no_window", False):
        return

    _orig_init = subprocess.Popen.__init__

    def _init(self, *args, **kwargs):
        # ``creationflags`` is positional index 14 of Popen.__init__ (after
        # self); nobody passes it positionally, so if it's set at all it's in
        # kwargs. OR the flag in — this both adds it where missing and leaves
        # call sites that already request CREATE_NO_WINDOW unchanged. Guard on
        # arg count so an (unheard-of) positional creationflags can't collide.
        if len(args) < 14:
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
        _orig_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _init
    subprocess.Popen._resistine_no_window = True
