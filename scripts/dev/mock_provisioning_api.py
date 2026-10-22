#!/usr/bin/env python3
"""Local stand-in for the Phoenix provisioning API (dev/testing only).

Implements the desktop-facing contract in
dev-docs/plans/vpn-provisioning-api.md so the app's VPN step can be exercised
before api.phoenix.exposed exists:

    POST   /v1/vpn/peer   {"public_key", "hostname"} -> WireGuard config
    DELETE /v1/device                                 -> 204

It does NOT check tokens with MAS: the Bearer token itself stands in for the
device identity. Addresses come from an in-memory table, so a device keeps
its address across calls until DELETE. Nothing is pushed to the router.

    python scripts/dev/mock_provisioning_api.py --port 8099
    PHOENIX_API_URL=http://127.0.0.1:8099 python main.py
"""

import argparse
import base64
import ipaddress
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER_PUBLIC_KEY = "u8909Yqge8GzXID9EPw5bEc0kN3PSC3AHvtbZagDeFo="  # router wg0
ENDPOINT = "vpn.phoenix.exposed:987"
NETWORK = ipaddress.ip_network("10.42.20.0/24")
FIRST_HOST = 10  # .1 is the router, .2-.9 are the hand-made test peers
DNS = ["10.42.20.1"]
ALLOWED_IPS = ["10.42.10.250/32", "10.42.20.1/32"]  # dashboard host + DNS
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

leases = {}  # device (bearer token) -> {"ip", "public_key", "psk"}


def _allocate(device):
    lease = leases.get(device)
    if lease:
        return lease
    used = {lease["ip"] for lease in leases.values()}
    for host in list(NETWORK.hosts())[FIRST_HOST - 1:]:
        if str(host) not in used:
            lease = {"ip": str(host),
                     "psk": base64.b64encode(os.urandom(32)).decode()}
            leases[device] = lease
            return lease
    raise RuntimeError("address pool exhausted")


class Handler(BaseHTTPRequestHandler):
    def _device(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") and len(auth) > 7 else None

    def _send(self, status, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        if self.path != "/v1/vpn/peer":
            return self._send(404, {"detail": "not found"})
        device = self._device()
        if not device:
            return self._send(401, {"detail": "missing bearer token"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except ValueError:
            return self._send(400, {"detail": "invalid JSON"})
        pub = body.get("public_key", "")
        if not _KEY_RE.match(pub):
            return self._send(422, {"detail": "public_key is not a WireGuard key"})
        lease = _allocate(device)
        lease["public_key"] = pub  # re-login: same device, same IP, new key
        self.log_message("peer %s -> %s (%s)", device[:8], lease["ip"], body.get("hostname"))
        self._send(200, {
            "Interface": {"Address": f"{lease['ip']}/32", "DNS": DNS},
            "Peer": {
                "PublicKey": SERVER_PUBLIC_KEY,
                "PresharedKey": lease["psk"],
                "Endpoint": ENDPOINT,
                "AllowedIPs": ALLOWED_IPS,
                "PersistentKeepalive": 25,
            },
        })

    def do_DELETE(self):  # noqa: N802
        if self.path != "/v1/device":
            return self._send(404, {"detail": "not found"})
        device = self._device()
        if not device:
            return self._send(401, {"detail": "missing bearer token"})
        lease = leases.pop(device, None)
        self.log_message("release %s (%s)", device[:8], lease and lease["ip"])
        self._send(204 if lease else 404, None if lease else {"detail": "unknown device"})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    print(f"mock provisioning API on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
