# Phoenix VPN provisioning API: contract

Status: desktop side implemented (`plugins/vpn/provisioning.py`), server side
to build on **briareosai** as `api.phoenix.exposed`. A local stand-in for
testing is `scripts/dev/mock_provisioning_api.py`
(`PHOENIX_API_URL=http://127.0.0.1:8099`).

Background and the device model: `phoenix-auth-rebrand.md`.

## Topology

```
Desktop ──HTTPS (Cloudflare tunnel)──▶ api.phoenix.exposed  (briareosai)
                                          │ introspect token ──▶ auth.phoenix.exposed (MAS)
                                          │ ssh (forced command) ──▶ 10.42.10.1 OpenWrt, wg0
Desktop ══WireGuard UDP 987══════════▶ vpn.phoenix.exposed (DNS-only record → router WAN)
```

- `api.phoenix.exposed` must be public (Cloudflare tunnel, Browser Integrity
  Check exception): the app calls it before any tunnel exists.
- `vpn.phoenix.exposed` must be a **DNS-only** (grey cloud) A record to the
  router's WAN address (83.208.45.10 today); Cloudflare's proxy can't carry
  UDP. If the address is dynamic, keep it current with `ddns-scripts`.
- Split tunnel: clients reach only the dashboard host and the router's DNS,
  which is exactly what the router's `vpn` firewall zone allows.

## Authentication

Every call carries `Authorization: Bearer <MAS access token>`. The API
introspects it at MAS (`/oauth2/introspect`, its own confidential client):

- `active` must be true, `client_id` must be the Phoenix Desktop client
- user = `username` (Matrix localpart) / `sub`
- device = the `urn:matrix:client:device:<ID>` entry in `scope` (`PHX_…`)

User and device always come from the token, never the request body.

## POST /v1/vpn/peer

Request:

```json
{"public_key": "<44-char WireGuard public key>", "hostname": "AnubisAI"}
```

`hostname` is a display label only.

Server steps:

1. Validate `public_key` (base64, 32 bytes).
2. Registry: if this device has a peer, keep its address and swap the key
   (a new key gets a new preshared key). If the device ID is registered to
   another account, refuse with 409: device IDs are only unique per user and
   the client picks its own, so a matching ID proves nothing. Otherwise
   allocate the next free address in `10.42.20.0/24` (from .10; .2-.9 are
   the hand-made test peers) and a fresh preshared key.
3. On the router: `phoenix-peer add <device_id> <public_key> <ip>`, the
   preshared key on stdin (never in argv: process lists, error messages).
4. Return the config.

Response 200 (the same shape the old `/verify-otp` returned):

```json
{
  "Interface": {"Address": "10.42.20.10/32", "DNS": ["10.42.20.1"]},
  "Peer": {
    "PublicKey": "u8909Yqge8GzXID9EPw5bEc0kN3PSC3AHvtbZagDeFo=",
    "PresharedKey": "<base64>",
    "Endpoint": "vpn.phoenix.exposed:987",
    "AllowedIPs": ["10.42.10.250/32", "10.42.20.1/32"],
    "PersistentKeepalive": 25
  }
}
```

The client validates every field and refuses newlines, script hooks and
malformed keys/addresses, so a compromised API can't inject `PostUp` lines.

## DELETE /v1/device

Removes this device's peer (`phoenix-peer del <device_id>`) and marks it
revoked. 204 on success, 404 if the device has no peer (the client treats
both as done). The app calls it on logout, before revoking its MAS session.

## Errors

| Status | Meaning | Client shows |
|---|---|---|
| 401 | token invalid/expired | refreshes once, then "Your Phoenix session ended. Sign in again." |
| 403 | account has no VPN entitlement | "Your Phoenix account doesn't include VPN access." |
| 409 | device ID registered to another account, or public key already in use | "Couldn't get a VPN config: <detail>" |
| 422 | bad `public_key` | the `detail` |
| 5xx / 503 | router or MAS unreachable | "Couldn't get a VPN config: <detail>" |

Error bodies: `{"detail": "<short, user-safe text>"}`.

## Registry

`user_id, device_id, mas_session_id, wg_pubkey, wg_ip, psk, wazuh_agent_id,
tenant, enrolled_at, last_seen, revoked_at`. SQLite is fine to start. The
router's uci peers carry `description=<device_id>`, so `phoenix-peer list`
can be reconciled against it.

## Router side (`/usr/libexec/phoenix-peer` on 10.42.10.1)

Reached over SSH with a dedicated key restricted in
`/etc/dropbear/authorized_keys`:

```
command="/usr/libexec/phoenix-peer",no-pty,no-port-forwarding,no-agent-forwarding,from="<briareosai IP>" ssh-ed25519 AAAA… phoenix-provisioning
```

- `add <device_id> <pubkey> <ip>` + psk on stdin: validate every argument strictly
  (`^PHX_[A-Z2-7]{16}$`, WireGuard key, IP inside 10.42.20.0/24), replace any
  existing peer with that description, `uci commit network`, apply live with
  `wg set wg0 peer …` (not `ifup wg0`, which drops every tunnel).
- `del <device_id>`: remove from uci and `wg set wg0 peer <key> remove`.
- `list`: `device_id ip pubkey latest-handshake` per managed peer.

## Revocation sync

A job in the API polls the MAS admin API for finished Phoenix Desktop
sessions and runs the same removal, so signing a device out in Element or
MAS `/account` also drops its VPN peer. Must be idempotent.

## Later

- Request signing with the device's Matrix ed25519 key (checked through
  Synapse `/keys/query`), once the desktop Matrix client publishes it.
- `/v1/wazuh/enroll` on the same API and registry.
