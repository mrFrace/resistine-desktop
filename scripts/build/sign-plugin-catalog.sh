#!/usr/bin/env bash

# Description: Sign the Store's plugin catalog (optional_plugins.json).
#   The app uses the catalog only with a valid minisign signature by a key
#   pinned in it (plugins/plugin_catalog.py): the catalog names each plugin's
#   archive and SHA-256, so it decides what code the app runs. This writes a
#   new "serial" into the catalog (the app refuses a catalog older than one it
#   has seen), checks every entry, and signs it with the desktop release key
#   (one password prompt) into <catalog>.minisig.
# Usage: ./scripts/build/sign-plugin-catalog.sh <path/to/optional_plugins.json>
#   Commit and push the catalog and its .minisig together. Any edit to the
#   catalog, even whitespace, needs a new signature. While the host serves a
#   new catalog with the old signature (or the reverse) the Store shows no
#   optional plugins.
#
#   PHOENIX_DESKTOP_KEY    minisign secret key (password-protected)
#                          default ~/.config/phoenix-release/desktop-minisign.key

set -euo pipefail

die() {
	echo "[sign-plugin-catalog.sh] ERROR: $1" >&2
	exit 1
}
log() { echo "[sign-plugin-catalog.sh] $1" >&2; }

[ $# -eq 1 ] || die "usage: sign-plugin-catalog.sh <path/to/optional_plugins.json>"
CATALOG="$1"
[ -s "$CATALOG" ] || die "no catalog at $CATALOG"
KEY="${PHOENIX_DESKTOP_KEY:-$HOME/.config/phoenix-release/desktop-minisign.key}"
[ -s "$KEY" ] || die "no signing key at $KEY"
if command -v minisign >/dev/null; then
	MINISIGN=(minisign)
else
	MINISIGN=(nix shell nixpkgs#minisign -c minisign)
fi

SERIAL="$(
	python3 -I - "$CATALOG" <<'PY'
import json, re, sys, time

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    catalog = json.load(f)
if not isinstance(catalog, dict) or not isinstance(catalog.get("plugins"), list):
    sys.exit('the catalog must be {"plugins": [...]}')
seen = set()
for i, p in enumerate(catalog["plugins"]):
    what = f"plugin #{i + 1}"
    if not isinstance(p, dict):
        sys.exit(f"{what}: not an object")
    if p.get("id") in (None, "") or str(p["id"]) in seen:
        sys.exit(f"{what}: missing or repeated id")
    seen.add(str(p["id"]))
    if not str(p.get("url", "")).startswith("https://"):
        sys.exit(f"{what} ({p['id']}): url must be https")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(p.get("sha256", ""))):
        sys.exit(f"{what} ({p['id']}): sha256 must be 64 hex digits")
old = catalog.get("serial")
serial = max(int(time.time()), old + 1 if isinstance(old, int) else 0)
catalog = {"serial": serial, **{k: v for k, v in catalog.items() if k != "serial"}}
with open(path, "w", encoding="utf-8") as f:
    json.dump(catalog, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(serial)
PY
)" || die "the catalog was not signed"

log "Signing $CATALOG (serial $SERIAL) with $KEY"
"${MINISIGN[@]}" -S -s "$KEY" -m "$CATALOG" -x "$CATALOG.minisig" -t "phoenix-plugins $SERIAL" >/dev/null
log "Wrote $CATALOG.minisig. Commit and push both files together."
