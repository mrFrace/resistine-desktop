"""Cross-signing for this Phoenix device: its status, and "verify with the
recovery key" (dev-docs/plans/device-sessions.md, sections 2 and 3).

matrix-nio has no cross-signing, so Element and Element X show every Phoenix
device as unverified. This module does the one thing Phoenix needs on top
of nio, with ``cryptography`` only:

- ``query_own_keys`` / ``device_status``: is a device of the account signed
  by the account's self-signing key, itself signed by the master key? The
  signatures are checked here; a status reported by the server is never
  trusted.
- ``verify_this_device``: open the self-signing key from secret storage
  (SSSS) with the recovery key the user has from Element, sign this
  device's keys with it and upload the signature.

The app never signs another device (decision 3 of the plan): that would be
trust on first use. The recovery key, the keys derived from it and the
self-signing seed only live in locals here; never in settings or logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import settings
from utils.logger import logger

_TIMEOUT = 15
_SSSS_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
_SSK_SECRET = "m.cross_signing.self_signing"
_RECOVERY_PREFIX = b"\x8b\x01"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

VERIFIED = "verified"
UNVERIFIED = "unverified"
NO_KEYS = "no_keys"
NO_CROSS_SIGNING = "no_cross_signing"


class VerificationError(Exception):
    """A failed verification. ``code`` picks the user-facing text
    (``devices.sessions_err_<code>``); ``detail`` is for the log only."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ---- encoding helpers ---------------------------------------------------------


def b64decode(s: str) -> bytes:
    """Matrix base64: standard alphabet, padding optional."""
    s = str(s).strip().rstrip("=")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def b64encode(b: bytes) -> str:
    """Unpadded standard base64, as Matrix writes it."""
    return base64.b64encode(b).decode("ascii").rstrip("=")


def canonical_json(obj: dict) -> bytes:
    """The signed form of a Matrix object: ``signatures`` and ``unsigned``
    removed, keys sorted, no whitespace, UTF-8."""
    body = {k: v for k, v in obj.items() if k not in ("signatures", "unsigned")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("not base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def decode_recovery_key(text: str) -> bytes:
    """The 32-byte secret-storage key from an Element recovery key
    ("EsTc 1234 ..."): base58, prefix 0x8B 0x01, parity byte."""
    compact = "".join(str(text).split())
    try:
        raw = _b58decode(compact)
    except ValueError:
        raise VerificationError("not_a_recovery_key") from None
    if len(raw) != 35 or raw[:2] != _RECOVERY_PREFIX:
        raise VerificationError("not_a_recovery_key")
    parity = 0
    for b in raw:
        parity ^= b
    if parity:
        raise VerificationError("not_a_recovery_key")
    return raw[2:34]


def _passphrase_key(passphrase: str, info: dict) -> bytes:
    """A secret-storage key derived from a passphrase (``m.pbkdf2``)."""
    if not isinstance(info, dict) or info.get("algorithm") != "m.pbkdf2":
        raise VerificationError("not_a_recovery_key")
    try:
        bits = int(info.get("bits") or 256)
        iterations = int(info["iterations"])
        salt = str(info["salt"]).encode("utf-8")
    except (KeyError, TypeError, ValueError):
        raise VerificationError("server", "bad passphrase parameters") from None
    if bits % 8 or not 0 < iterations <= 10_000_000:
        raise VerificationError("server", "bad passphrase parameters")
    return PBKDF2HMAC(algorithm=hashes.SHA512(), length=bits // 8, salt=salt,
                      iterations=iterations).derive(passphrase.encode("utf-8"))


# ---- secret storage (SSSS, m.secret_storage.v1.aes-hmac-sha2) -----------------


def _ssss_keys(key: bytes, name: str) -> tuple[bytes, bytes]:
    out = HKDF(algorithm=hashes.SHA256(), length=64, salt=b"\x00" * 32,
               info=name.encode("utf-8")).derive(key)
    return out[:32], out[32:]


def _aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def ssss_encrypt(key: bytes, name: str, plaintext: bytes, iv: bytes) -> dict:
    """{iv, ciphertext, mac} as secret storage writes them (used by the key
    check and the tests)."""
    aes_key, mac_key = _ssss_keys(key, name)
    ciphertext = _aes_ctr(aes_key, iv, plaintext)
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return {"iv": b64encode(iv), "ciphertext": b64encode(ciphertext), "mac": b64encode(mac)}


def check_ssss_key(key: bytes, description: dict) -> bool:
    """Whether ``key`` is the key ``description`` (the
    ``m.secret_storage.key.<id>`` account data) was made with: 32 zero
    bytes encrypted with the name "" must give its ``mac``."""
    try:
        iv = b64decode(description["iv"])
        expected = b64decode(description["mac"])
    except (KeyError, TypeError, ValueError):
        return False
    got = b64decode(ssss_encrypt(key, "", b"\x00" * 32, iv)["mac"])
    return hmac.compare_digest(got, expected)


def ssss_decrypt(key: bytes, name: str, encrypted: dict) -> bytes:
    """The plaintext of one secret-storage entry; VerificationError when its
    MAC does not match."""
    try:
        iv = b64decode(encrypted["iv"])
        ciphertext = b64decode(encrypted["ciphertext"])
        mac = b64decode(encrypted["mac"])
    except (KeyError, TypeError, ValueError):
        raise VerificationError("server", f"malformed secret {name}") from None
    aes_key, mac_key = _ssss_keys(key, name)
    if not hmac.compare_digest(hmac.new(mac_key, ciphertext, hashlib.sha256).digest(), mac):
        raise VerificationError("wrong_key", f"MAC mismatch on {name}")
    return _aes_ctr(aes_key, iv, ciphertext)


# ---- signatures and status ----------------------------------------------------


def _ed25519_of(key_obj: Optional[dict]) -> Optional[str]:
    """The (single) ed25519 public key of a cross-signing key object."""
    if not isinstance(key_obj, dict) or not isinstance(key_obj.get("keys"), dict):
        return None
    for kid, pub in key_obj["keys"].items():
        if str(kid).startswith("ed25519:") and isinstance(pub, str):
            return pub
    return None


def signed_by(obj: Optional[dict], user_id: str, public_key: Optional[str]) -> bool:
    """Whether ``obj`` carries a valid signature of ``user_id``'s
    ed25519 key ``public_key``."""
    if not isinstance(obj, dict) or not public_key:
        return False
    sigs = obj.get("signatures")
    mine = sigs.get(user_id) if isinstance(sigs, dict) else None
    sig = mine.get(f"ed25519:{public_key}") if isinstance(mine, dict) else None
    if not isinstance(sig, str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(public_key)).verify(
            b64decode(sig), canonical_json(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class OwnKeys:
    """The account's own keys as ``/keys/query`` returned them."""
    user_id: str
    master: Optional[dict] = None
    self_signing: Optional[dict] = None
    devices: dict = field(default_factory=dict)  # device_id -> device keys

    @property
    def master_key(self) -> Optional[str]:
        return _ed25519_of(self.master)

    @property
    def self_signing_key(self) -> Optional[str]:
        return _ed25519_of(self.self_signing)


def parse_keys_query(user_id: str, body: dict) -> OwnKeys:
    body = body if isinstance(body, dict) else {}

    def pick(section):
        v = body.get(section)
        v = v.get(user_id) if isinstance(v, dict) else None
        return v if isinstance(v, dict) else None

    devices = pick("device_keys") or {}
    return OwnKeys(user_id, pick("master_keys"), pick("self_signing_keys"),
                   {k: v for k, v in devices.items() if isinstance(v, dict)})


def device_status(own: OwnKeys, device_id: str) -> str:
    """verified | unverified | no_keys | no_cross_signing, from signatures
    checked here: the device signed by the self-signing key, and that key
    signed by the master key."""
    master, ssk = own.master_key, own.self_signing_key
    if not master or not ssk:
        return NO_CROSS_SIGNING
    device = own.devices.get(device_id)
    if not device:
        return NO_KEYS
    if signed_by(own.self_signing, own.user_id, master) and signed_by(device, own.user_id, ssk):
        return VERIFIED
    return UNVERIFIED


# ---- HTTP (the homeserver, as this session) -----------------------------------


def _identity() -> tuple[str, str]:
    user_id = settings.get("auth", "user_id") or ""
    device_id = settings.get("auth", "device_id") or ""
    if not user_id or not device_id:
        raise VerificationError("not_signed_in")
    return user_id, device_id


def _request(method: str, path: str, body: Optional[dict] = None):
    """A Client-Server API call with this session's token: (status, json).
    404 answers (no such account data) come back as (404, None)."""
    from plugins.login import oidc

    try:
        token = oidc.refresh()
    except oidc.OIDCError as e:
        raise VerificationError("network", str(e)) from e
    if not token:
        raise VerificationError("not_signed_in")
    http = oidc._session()
    url = oidc.homeserver_url() + path
    for attempt in (1, 2):
        try:
            r = http.request(method, url, json=body, timeout=_TIMEOUT, verify=True,
                             allow_redirects=False,
                             headers={"Authorization": f"Bearer {token}"})
        except Exception as e:  # noqa: BLE001 - a transport failure is an error code
            raise VerificationError("network", type(e).__name__) from e
        if r.status_code == 401 and attempt == 1:
            token = oidc.refresh(force=True)
            if not token:
                raise VerificationError("not_signed_in")
            continue
        break
    if r.status_code == 404:
        return 404, None
    try:
        data = r.json()
    except ValueError:
        data = None
    if r.status_code != 200:
        raise VerificationError("server", f"{method} {path.split('?')[0]}: HTTP {r.status_code}")
    return 200, data


def _account_data(user_id: str, kind: str) -> Optional[dict]:
    _, data = _request("GET", f"/_matrix/client/v3/user/{quote(user_id, safe='')}"
                              f"/account_data/{quote(kind, safe='')}")
    return data if isinstance(data, dict) else None


def query_own_keys() -> OwnKeys:
    user_id, _ = _identity()
    _, body = _request("POST", "/_matrix/client/v3/keys/query",
                       {"device_keys": {user_id: []}})
    return parse_keys_query(user_id, body or {})


def this_device_status() -> str:
    """This device's status; VerificationError when it can't be asked."""
    _, device_id = _identity()
    return device_status(query_own_keys(), device_id)


def _own_identity_key(user_id: str, device_id: str) -> Optional[str]:
    """This device's ed25519 identity key from nio's own store (None when
    the Matrix connection isn't up)."""
    from plugins.chat import matrix_transport

    return matrix_transport.own_identity_key(user_id, device_id)


# ---- verify this device -------------------------------------------------------


def _storage_key(secret: str, user_id: str) -> tuple[str, bytes]:
    """(key id, key) of the account's default secret-storage key, opened
    with a recovery key or, failing that, a passphrase."""
    default = _account_data(user_id, "m.secret_storage.default_key")
    key_id = default.get("key") if default else None
    if not isinstance(key_id, str) or not key_id:
        raise VerificationError("no_cross_signing", "no default secret-storage key")
    desc = _account_data(user_id, f"m.secret_storage.key.{key_id}")
    if not desc or desc.get("algorithm") != _SSSS_ALGORITHM:
        raise VerificationError("unsupported", f"secret storage {desc and desc.get('algorithm')}")
    try:
        key = decode_recovery_key(secret)
    except VerificationError:
        if not desc.get("passphrase"):
            raise
        key = _passphrase_key(secret, desc["passphrase"])
    if not check_ssss_key(key, desc):
        raise VerificationError("wrong_key")
    return key_id, key


def verify_this_device(secret: str) -> None:
    """Sign this device with the account's self-signing key, opened from
    secret storage with ``secret`` (the recovery key, or the secret-storage
    passphrase). Raises VerificationError; returns when the signature is
    uploaded."""
    user_id, device_id = _identity()
    own = query_own_keys()
    if not own.master_key or not own.self_signing_key:
        raise VerificationError("no_cross_signing")
    if not signed_by(own.self_signing, user_id, own.master_key):
        raise VerificationError("identity_mismatch", "self-signing key not signed by master")

    key_id, key = _storage_key(secret, user_id)
    stored = _account_data(user_id, _SSK_SECRET)
    entries = stored.get("encrypted") if stored else None
    encrypted = entries.get(key_id) if isinstance(entries, dict) else None
    if not isinstance(encrypted, dict):
        raise VerificationError("no_cross_signing", "self-signing key not in secret storage")
    try:
        seed = b64decode(ssss_decrypt(key, _SSK_SECRET, encrypted).decode("ascii"))
        signer = Ed25519PrivateKey.from_private_bytes(seed)
    except (ValueError, UnicodeDecodeError):
        raise VerificationError("server", "self-signing secret is not an ed25519 seed") from None
    pub = b64encode(signer.public_key().public_bytes_raw())
    if pub != own.self_signing_key:
        raise VerificationError("identity_mismatch", "secret storage holds another self-signing key")

    device = own.devices.get(device_id)
    if not device:
        raise VerificationError("no_device_keys")
    published = (device.get("keys") or {}).get(f"ed25519:{device_id}")
    ours = _own_identity_key(user_id, device_id)
    if not ours:
        raise VerificationError("not_connected")
    if published != ours:
        raise VerificationError("device_key_mismatch", "published keys are not this install's")

    signature = b64encode(signer.sign(canonical_json(device)))
    signed = {k: v for k, v in device.items() if k not in ("signatures", "unsigned")}
    signed["signatures"] = {user_id: {f"ed25519:{pub}": signature}}
    _, resp = _request("POST", "/_matrix/client/v3/keys/signatures/upload",
                       {user_id: {device_id: signed}})
    failures = (resp or {}).get("failures") if isinstance(resp, dict) else None
    if failures:
        raise VerificationError("upload_failed", json.dumps(failures)[:300])
    logger.info(f"[CROSS-SIGNING] signed device {device_id} with the self-signing key")
