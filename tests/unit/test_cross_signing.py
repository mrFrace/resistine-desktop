"""Cross-signing: recovery key, secret storage, signature checks, and
verify_this_device end to end against a fake homeserver
(plugins/login/cross_signing.py)."""

import json
import logging
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.login import cross_signing as cs

pytestmark = pytest.mark.unit

USER = "@drake:phoenix.exposed"
DEVICE = "PHX_QS3ZBL42VSZ6YQAJ"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def recovery_key(key: bytes) -> str:
    raw = b"\x8b\x01" + key
    parity = 0
    for b in raw:
        parity ^= b
    text = b58encode(raw + bytes([parity]))
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


def pub(priv: Ed25519PrivateKey) -> str:
    return cs.b64encode(priv.public_key().public_bytes_raw())


def sign(obj: dict, priv: Ed25519PrivateKey) -> dict:
    sig = cs.b64encode(priv.sign(cs.canonical_json(obj)))
    out = dict(obj)
    out.setdefault("signatures", {}).setdefault(USER, {})[f"ed25519:{pub(priv)}"] = sig
    return out


class Account:
    """A homeserver's view of one account with cross-signing set up."""

    def __init__(self, passphrase=None):
        self.master = Ed25519PrivateKey.generate()
        self.ssk = Ed25519PrivateKey.generate()
        self.device = Ed25519PrivateKey.generate()  # the device's own identity key
        self.key = os.urandom(32)
        self.key_id = "abcDEF123"
        mk = pub(self.master)
        self.master_obj = sign({"user_id": USER, "usage": ["master"],
                                "keys": {f"ed25519:{mk}": mk}}, self.master)
        sk = pub(self.ssk)
        self.ssk_obj = sign({"user_id": USER, "usage": ["self_signing"],
                             "keys": {f"ed25519:{sk}": sk}}, self.master)
        dk = pub(self.device)
        self.device_obj = sign({"user_id": USER, "device_id": DEVICE,
                                "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                                "keys": {f"ed25519:{DEVICE}": dk, f"curve25519:{DEVICE}": "c" * 43}},
                               self.device)
        check = cs.ssss_encrypt(self.key, "", b"\0" * 32, os.urandom(16))
        self.key_desc = {"algorithm": "m.secret_storage.v1.aes-hmac-sha2",
                         "iv": check["iv"], "mac": check["mac"]}
        if passphrase:
            self.key_desc["passphrase"] = passphrase
        seed = self.ssk.private_bytes_raw()
        self.account_data = {
            "m.secret_storage.default_key": {"key": self.key_id},
            f"m.secret_storage.key.{self.key_id}": self.key_desc,
            "m.cross_signing.self_signing": {"encrypted": {self.key_id: cs.ssss_encrypt(
                self.key, "m.cross_signing.self_signing", cs.b64encode(seed).encode(),
                os.urandom(16))}},
        }
        self.uploads = []

    def keys_query(self):
        return {"device_keys": {USER: {DEVICE: self.device_obj}},
                "master_keys": {USER: self.master_obj},
                "self_signing_keys": {USER: self.ssk_obj}}

    def request(self, method, path, body=None):
        if path == "/_matrix/client/v3/keys/query":
            return 200, self.keys_query()
        if path == "/_matrix/client/v3/keys/signatures/upload":
            self.uploads.append(body)
            return 200, {"failures": {}}
        prefix = "/_matrix/client/v3/user/%40drake%3Aphoenix.exposed/account_data/"
        assert path.startswith(prefix), path
        kind = path[len(prefix):]
        return (200, self.account_data[kind]) if kind in self.account_data else (404, None)


@pytest.fixture
def account(monkeypatch):
    acc = Account()
    store = {("auth", "user_id"): USER, ("auth", "device_id"): DEVICE}
    monkeypatch.setattr(cs.settings, "get", lambda ns, k, d=None: store.get((ns, k), d))
    monkeypatch.setattr(cs.settings, "set", lambda *a, **k: pytest.fail("settings written"))
    monkeypatch.setattr(cs, "_request", acc.request)
    monkeypatch.setattr(cs, "_own_identity_key", lambda u, d: pub(acc.device))
    return acc


# ---- recovery key -------------------------------------------------------------


def test_recovery_key_round_trip():
    key = os.urandom(32)
    assert cs.decode_recovery_key(recovery_key(key)) == key


def test_recovery_key_spaces_and_newlines_ignored():
    key = os.urandom(32)
    assert cs.decode_recovery_key("  " + recovery_key(key).replace(" ", "\n ") + " ") == key


@pytest.mark.parametrize("mangle", [
    lambda raw: b"\x8b\x02" + raw[2:],          # bad prefix
    lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]),  # bad parity
    lambda raw: raw[:-2] + raw[-1:],             # wrong length
])
def test_recovery_key_rejected(mangle):
    key = os.urandom(32)
    raw = b"\x8b\x01" + key
    parity = 0
    for b in raw:
        parity ^= b
    bad = b58encode(mangle(raw + bytes([parity])))
    with pytest.raises(cs.VerificationError) as e:
        cs.decode_recovery_key(bad)
    assert e.value.code == "not_a_recovery_key"


def test_recovery_key_not_base58():
    with pytest.raises(cs.VerificationError) as e:
        cs.decode_recovery_key("EsT0 OOOO llll")
    assert e.value.code == "not_a_recovery_key"


# ---- secret storage -------------------------------------------------------------


def test_ssss_key_check():
    acc = Account()
    assert cs.check_ssss_key(acc.key, acc.key_desc)
    assert not cs.check_ssss_key(os.urandom(32), acc.key_desc)


def test_ssss_decrypt_and_wrong_key():
    acc = Account()
    enc = acc.account_data["m.cross_signing.self_signing"]["encrypted"][acc.key_id]
    seed = cs.b64decode(cs.ssss_decrypt(acc.key, "m.cross_signing.self_signing", enc).decode())
    assert seed == acc.ssk.private_bytes_raw()
    with pytest.raises(cs.VerificationError) as e:
        cs.ssss_decrypt(os.urandom(32), "m.cross_signing.self_signing", enc)
    assert e.value.code == "wrong_key"


def test_ssss_decrypt_checks_the_secret_name():
    acc = Account()
    enc = acc.account_data["m.cross_signing.self_signing"]["encrypted"][acc.key_id]
    with pytest.raises(cs.VerificationError):
        cs.ssss_decrypt(acc.key, "m.cross_signing.master", enc)


# ---- signatures and status ------------------------------------------------------


def test_canonical_json_drops_signatures_and_unsigned():
    obj = {"b": 1, "a": "č", "signatures": {"x": 1}, "unsigned": {"y": 2}}
    assert cs.canonical_json(obj) == '{"a":"č","b":1}'.encode()


def _own(acc, device=None, ssk=None):
    return cs.parse_keys_query(USER, {
        "device_keys": {USER: {DEVICE: device or acc.device_obj}},
        "master_keys": {USER: acc.master_obj},
        "self_signing_keys": {USER: ssk or acc.ssk_obj}})


def test_status_unverified_until_signed_by_ssk():
    acc = Account()
    assert cs.device_status(_own(acc), DEVICE) == cs.UNVERIFIED
    assert cs.device_status(_own(acc, device=sign(acc.device_obj, acc.ssk)), DEVICE) == cs.VERIFIED


def test_status_tampered_device_is_unverified():
    acc = Account()
    signed = sign(acc.device_obj, acc.ssk)
    signed["keys"] = {**signed["keys"], f"ed25519:{DEVICE}": pub(Ed25519PrivateKey.generate())}
    assert cs.device_status(_own(acc, device=signed), DEVICE) == cs.UNVERIFIED


def test_status_ssk_not_signed_by_master_is_unverified():
    acc = Account()
    stray = {k: v for k, v in acc.ssk_obj.items() if k != "signatures"}
    own = _own(acc, device=sign(acc.device_obj, acc.ssk), ssk=stray)
    assert cs.device_status(own, DEVICE) == cs.UNVERIFIED


def test_status_no_cross_signing_and_no_keys():
    assert cs.device_status(cs.parse_keys_query(USER, {}), DEVICE) == cs.NO_CROSS_SIGNING
    acc = Account()
    assert cs.device_status(_own(acc), "PHX_AAAAAAAAAAAAAAAA") == cs.NO_KEYS


def test_garbage_keys_query_does_not_crash():
    own = cs.parse_keys_query(USER, {"device_keys": {USER: {DEVICE: "x"}}, "master_keys": [],
                                     "self_signing_keys": {USER: {"keys": 5, "signatures": "s"}}})
    assert cs.device_status(own, DEVICE) == cs.NO_CROSS_SIGNING
    assert not cs.signed_by({"signatures": {USER: "x"}}, USER, pub(Ed25519PrivateKey.generate()))


# ---- verify_this_device ---------------------------------------------------------


def test_verify_uploads_a_signature_the_ssk_verifies(account, caplog):
    secret = recovery_key(account.key)
    with caplog.at_level(logging.DEBUG):
        cs.verify_this_device(secret)
    [upload] = account.uploads
    signed = upload[USER][DEVICE]
    assert cs.signed_by(signed, USER, pub(account.ssk))
    assert set(signed["signatures"][USER]) == {f"ed25519:{pub(account.ssk)}"}
    # The uploaded object is the published device keys, now verified.
    account.device_obj = {**account.device_obj,
                          "signatures": {USER: {**account.device_obj["signatures"][USER],
                                                **signed["signatures"][USER]}}}
    assert cs.this_device_status() == cs.VERIFIED
    logged = caplog.text + json.dumps(account.uploads)
    assert secret not in logged and secret.replace(" ", "") not in logged
    assert cs.b64encode(account.ssk.private_bytes_raw()) not in logged


def test_verify_wrong_recovery_key(account):
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(os.urandom(32)))
    assert e.value.code == "wrong_key"
    assert account.uploads == []


def test_verify_with_passphrase(monkeypatch):
    acc = Account(passphrase={"algorithm": "m.pbkdf2", "salt": "saltsalt", "iterations": 1000})
    acc.key = cs._passphrase_key("correct horse", acc.key_desc["passphrase"])
    check = cs.ssss_encrypt(acc.key, "", b"\0" * 32, os.urandom(16))
    acc.key_desc.update(iv=check["iv"], mac=check["mac"])
    acc.account_data["m.cross_signing.self_signing"]["encrypted"][acc.key_id] = cs.ssss_encrypt(
        acc.key, "m.cross_signing.self_signing",
        cs.b64encode(acc.ssk.private_bytes_raw()).encode(), os.urandom(16))
    store = {("auth", "user_id"): USER, ("auth", "device_id"): DEVICE}
    monkeypatch.setattr(cs.settings, "get", lambda ns, k, d=None: store.get((ns, k), d))
    monkeypatch.setattr(cs, "_request", acc.request)
    monkeypatch.setattr(cs, "_own_identity_key", lambda u, d: pub(acc.device))
    cs.verify_this_device("correct horse")
    assert len(acc.uploads) == 1
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device("wrong horse")
    assert e.value.code == "wrong_key"


def test_verify_refuses_keys_that_are_not_this_install(account, monkeypatch):
    monkeypatch.setattr(cs, "_own_identity_key", lambda u, d: pub(Ed25519PrivateKey.generate()))
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(account.key))
    assert e.value.code == "device_key_mismatch"
    assert account.uploads == []


def test_verify_needs_the_matrix_connection(account, monkeypatch):
    monkeypatch.setattr(cs, "_own_identity_key", lambda u, d: None)
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(account.key))
    assert e.value.code == "not_connected"


def test_verify_refuses_storage_with_another_ssk(account):
    other = Ed25519PrivateKey.generate()
    account.account_data["m.cross_signing.self_signing"]["encrypted"][account.key_id] = cs.ssss_encrypt(
        account.key, "m.cross_signing.self_signing",
        cs.b64encode(other.private_bytes_raw()).encode(), os.urandom(16))
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(account.key))
    assert e.value.code == "identity_mismatch"
    assert account.uploads == []


def test_verify_without_cross_signing(account):
    account.master_obj = None
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(account.key))
    assert e.value.code == "no_cross_signing"


def test_verify_reports_upload_failures(account, monkeypatch):
    real = account.request

    def failing(method, path, body=None):
        if path.endswith("/keys/signatures/upload"):
            return 200, {"failures": {USER: {DEVICE: {"errcode": "M_INVALID_SIGNATURE"}}}}
        return real(method, path, body)

    monkeypatch.setattr(cs, "_request", failing)
    with pytest.raises(cs.VerificationError) as e:
        cs.verify_this_device(recovery_key(account.key))
    assert e.value.code == "upload_failed"


# ---- known vectors (keys made by Element; as in mautrix-python's ssss/key_test.py) ----

VEC_META = {
    "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
    "passphrase": {"algorithm": "m.pbkdf2", "iterations": 500000,
                   "salt": "y863BOoqOadgDp8S3FtHXikDJEalsQ7d"},
    "iv": "xxkTK0L4UzxgAFkQ6XPwsw",
    "mac": "MEhooO0ZhFJNxUhvRMSxBnJfL20wkLgle3ocY0ee/eA",
}
VEC_RECOVERY_KEY = "EsTE s92N EtaX s2h6 VQYF 9Kao tHYL mkyL GKMh isZb KJ4E tvoC"
VEC_PASSPHRASE = "correct horse battery staple"
VEC_MASTER = {"iv": "BpKP9nQJTE9jrsAssoxPqQ==",
              "ciphertext": "fNRiiiidezjerTgV+G6pUtmeF3izzj5re/mVvY0hO2kM6kYGrxLuIu2ej80=",
              "mac": "/gWGDGMyOLmbJp+aoSLh5JxCs0AdS6nAhjzpe+9G2Q0="}
VEC_MASTER_SEED = bytes.fromhex("68f97fd1922eecf6b82bb890d24d0652984e7a1d703b9e867b7ebaf7feb95b6f")
VEC_OTHER_RECOVERY_KEY = "EsUC xSxt XJgQ dz19 8WBZ rHdE GZo7 ybsn EFmG Y5HY MDAG GNWe"


def test_vector_recovery_key_opens_storage_and_decrypts():
    key = cs.decode_recovery_key(VEC_RECOVERY_KEY)
    assert cs.check_ssss_key(key, VEC_META)
    plain = cs.ssss_decrypt(key, "m.cross_signing.master", VEC_MASTER)
    assert cs.b64decode(plain.decode()) == VEC_MASTER_SEED


@pytest.mark.slow
def test_vector_passphrase_gives_the_same_key():
    key = cs._passphrase_key(VEC_PASSPHRASE, VEC_META["passphrase"])
    assert key == cs.decode_recovery_key(VEC_RECOVERY_KEY)


def test_vector_other_key_is_refused():
    key = cs.decode_recovery_key(VEC_OTHER_RECOVERY_KEY)
    assert not cs.check_ssss_key(key, VEC_META)
    with pytest.raises(cs.VerificationError):
        cs.ssss_decrypt(key, "m.cross_signing.master", VEC_MASTER)
