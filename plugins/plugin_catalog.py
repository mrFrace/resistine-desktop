"""The signed catalog of Store plugins.

The catalog (``optional_plugins.json``) names each plugin's archive and its
SHA-256, so whoever writes it chooses what code this app runs. It is therefore
trusted only with a minisign signature (``optional_plugins.json.minisig``,
fetched from the same place) by a key pinned in the app, the same keys a
desktop release is signed with. Where the two files are hosted no longer
matters.

    {"serial": 1766400000, "plugins": [{"id": ..., "url": ..., "sha256": ...}]}

The signed trusted comment is ``phoenix-plugins <serial>``: a signature made
for a desktop release is not one for a catalog (or the other way round), and
the serial lets the app refuse a catalog older than one it has already seen,
which could offer a withdrawn plugin again.
``scripts/build/sign-plugin-catalog.sh`` writes the serial and signs.
"""

import json
from typing import Optional

from plugins.wazuh.agent import phoenix_packages as pp

CATALOG = "phoenix-plugins"
SIGNATURE_SUFFIX = ".minisig"
MAX_CATALOG = 256 * 1024
MAX_SIGNATURE = 4 * 1024


class CatalogError(Exception):
    """The catalog can't be trusted; nothing from it may be used."""


def public_keys() -> tuple[str, ...]:
    """Every key the catalog may be signed with."""
    return pp.desktop_public_keys()


def parse(data: bytes, signature: str,
          keys: Optional[tuple[str, ...]] = None) -> tuple[int, list]:
    """Verify the catalog; return ``(serial, plugins)``.

    Raises CatalogError when the signature is missing, malformed, by an
    unknown key or not for these bytes, or the catalog is malformed.
    """
    try:
        trusted_comment = pp.verify_minisign(
            data, signature, pp._key_for(signature, keys or public_keys()))
    except pp.PackageError as e:
        raise CatalogError(f"The plugin catalog is not signed by Phoenix: {e}") from e
    try:
        catalog = json.loads(data)
    except ValueError as e:
        raise CatalogError("The plugin catalog is not valid JSON.") from e
    if not isinstance(catalog, dict):
        raise CatalogError("The plugin catalog is malformed.")
    serial = catalog.get("serial")
    plugins = catalog.get("plugins")
    if isinstance(serial, bool) or not isinstance(serial, int) or serial <= 0 \
            or not isinstance(plugins, list):
        raise CatalogError("The plugin catalog is malformed.")
    if trusted_comment != f"{CATALOG} {serial}":
        raise CatalogError("The signature is not for this plugin catalog.")
    return serial, [p for p in plugins if isinstance(p, dict)]
