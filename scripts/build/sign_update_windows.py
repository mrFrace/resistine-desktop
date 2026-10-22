#!/usr/bin/env python3
"""
Windows Sparkle/WinSparkle release signing tool.

Signs release artifacts with Ed25519 for WinSparkle signature verification.
Private key is stored in Windows Credential Manager via keyring.

Usage:
    python sign_update_windows.py <path/to/file>
    python sign_update_windows.py --store-key
    python sign_update_windows.py --delete-key

Output (when signing):
    sparkle:edSignature="BASE64SIG" length="BYTES"
"""

import base64
import getpass
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SERVICE = "Resistine"
_USERNAME = "sparkle-ed-private-key"


def _get_key_from_keyring():
    """Retrieve the private key from the OS credential store."""
    try:
        import keyring

        return keyring.get_password(_SERVICE, _USERNAME)
    except Exception:
        return None


def _store_key():
    """Prompt for the base64 private key and save to credential store."""
    import keyring

    print("Paste SPARKLE_ED_PRIVATE_KEY (base64):")
    key_b64 = input().strip()
    if not key_b64:
        print("Error: empty key", file=sys.stderr)
        sys.exit(1)

    # Validate the key before storing
    # Sparkle keys may be 64 bytes (seed + public key) or 33 bytes
    # (seed + trailing byte from export). We need exactly 32 bytes.
    try:
        raw = base64.b64decode(key_b64)
        seed = raw[:32]
        Ed25519PrivateKey.from_private_bytes(seed)
    except Exception as exc:
        print(f"Error: invalid Ed25519 key — {exc}", file=sys.stderr)
        sys.exit(1)

    keyring.set_password(_SERVICE, _USERNAME, key_b64)
    print(f"Key stored in credential manager ({_SERVICE}/{_USERNAME})")


def _delete_key():
    """Remove the private key from the credential store."""
    import keyring

    try:
        keyring.delete_password(_SERVICE, _USERNAME)
        print(f"Key deleted from credential manager ({_SERVICE}/{_USERNAME})")
    except keyring.errors.PasswordDeleteError:
        print("No key found in credential manager", file=sys.stderr)


def _sign(path):
    """Sign a file and print the Sparkle-format signature."""
    # 1) Try keyring
    key_b64 = _get_key_from_keyring()

    # 2) Fall back to env var (for CI)
    if not key_b64:
        key_b64 = os.environ.get("SPARKLE_ED_PRIVATE_KEY", "").strip()

    if not key_b64:
        print(
            "Error: no key found. Run --store-key or set "
            "SPARKLE_ED_PRIVATE_KEY env var.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    raw = base64.b64decode(key_b64)
    seed = raw[:32]
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    data = open(path, "rb").read()
    sig = base64.b64encode(private_key.sign(data)).decode()
    length = len(data)
    print(f'sparkle:edSignature="{sig}" length="{length}"')


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "--store-key":
        _store_key()
    elif arg == "--delete-key":
        _delete_key()
    else:
        _sign(arg)


if __name__ == "__main__":
    main()
