"""Thin re-export shim — canonical source is plugins/vpn/wireguard/windows_vpn_service.py.

This module exists so test imports like `from services.windows_vpn_service import ...`
continue to work without changing 90+ test files. Do not add logic here.
"""

from plugins.vpn.wireguard.windows_vpn_service import *  # noqa: F401,F403
