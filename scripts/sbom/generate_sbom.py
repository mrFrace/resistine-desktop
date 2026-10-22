#!/usr/bin/env python3
"""Generate Phoenix's SBOM and human-readable license attribution doc.

Produces TWO artifacts at the repo root:

    sbom.cdx.json          CycloneDX 1.6 JSON. Machine-readable bill of
                           materials. Suitable for Dependency-Track, Snyk,
                           OWASP DT, procurement reviews.

    LICENSE-3rd-Party.md   Human-readable Markdown derived from the SBOM.
                           Shipped inside the installer next to LICENSE.md.

How it works
------------
1.  Run ``cyclonedx-py environment`` against the currently active venv.
    This walks every installed distribution's metadata and emits a full
    CycloneDX SBOM (one ``component`` per Python package, with name,
    version, PURL, license, hashes, dependency edges).
2.  Merge in ``scripts/sbom/sbom-bundled.json`` — hand-maintained
    CycloneDX components for non-Python things we ship or install
    (ClamAV, WireGuard, Wazuh, ``resistine-vpn-cli``).
3.  Enforce the license deny-list (AGPL / SSPL / BUSL / Commons Clause)
    against every component, including bundled ones. Fail-loud if any
    match, so the build can't ship a license incompatible with our
    GPL-2.0-or-later distribution.
4.  Write ``sbom.cdx.json`` deterministically (sorted components, no
    timestamp churn — uses ``--output-reproducible`` from cyclonedx-py).
5.  Render ``LICENSE-3rd-Party.md`` from the merged SBOM. Uses
    ``license-3rd-party-header.md`` as the intro.

Run me
------
Easy mode (recommended — uses an isolated prod venv at ``.sbom-venv/``)::

    ./scripts/sbom/run.sh

Direct mode (you handle the venv isolation yourself)::

    source .venv-prod/bin/activate
    pip install "cyclonedx-bom>=7.0.0"
    python scripts/sbom/generate_sbom.py

CI runs the direct form against a clean venv it provisions per job and
verifies the committed files match with ``--check``.

Author: Resistine Team
Copyright (c) Resistine 2026
Licensed under the GNU General Public License v2 or later
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

SBOM_PATH = REPO_ROOT / "sbom.cdx.json"
LICENSE_MD_PATH = REPO_ROOT / "LICENSE-3rd-Party.md"
HEADER_MD_PATH = SCRIPT_DIR / "license-3rd-party-header.md"
BUNDLED_JSON_PATH = SCRIPT_DIR / "sbom-bundled.json"

# Licenses we cannot distribute alongside our GPL-2.0-or-later codebase.
# Substring match is case-insensitive against component license id, name,
# and SPDX expression. Conservative on purpose — adding a dep with a name
# that includes any of these should be a deliberate review, not a silent
# ship. See LICENSE-3rd-Party.md notes for rationale.
DENY_LICENSE_FRAGMENTS = (
    "agpl",
    "affero general public license",
    "sspl",
    "server side public license",
    "busl",
    "business source license",
    "commons clause",
)


def run_cyclonedx() -> dict:
    """Run cyclonedx-py against the active venv and return parsed SBOM."""
    try:
        out = subprocess.check_output(
            [
                sys.executable, "-m", "cyclonedx_py", "environment",
                "--of", "JSON",
                "--output-reproducible",
                "--validate",
            ],
            text=True,
        )
    except FileNotFoundError:
        sys.stderr.write(
            "ERROR: cyclonedx-bom is not installed in this environment.\n"
            "       pip install 'cyclonedx-bom>=7.0.0'\n"
        )
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(
            f"ERROR: cyclonedx-py environment failed (exit {e.returncode}).\n"
        )
        sys.exit(2)
    return json.loads(out)


def merge_bundled(sbom: dict) -> dict:
    """Merge hand-maintained non-Python components into the SBOM."""
    if not BUNDLED_JSON_PATH.exists():
        return sbom
    bundled = json.loads(BUNDLED_JSON_PATH.read_text(encoding="utf-8"))
    extras = bundled.get("components", [])
    sbom.setdefault("components", []).extend(extras)
    # Deterministic ordering — important so CI's git-diff freshness check
    # doesn't see noise from cyclonedx-py's internal ordering.
    sbom["components"].sort(key=lambda c: c.get("name", "").lower())
    return sbom


def license_strings(component: dict):
    """Yield every human-readable license fragment for one component."""
    for entry in component.get("licenses", []) or []:
        lic = entry.get("license", {}) or {}
        for key in ("id", "name"):
            v = lic.get(key)
            if v:
                yield str(v)
        expr = entry.get("expression")
        if expr:
            yield str(expr)


def enforce_policy(sbom: dict) -> None:
    """Fail the build if any component carries a denied license."""
    violations = []
    for c in sbom.get("components", []):
        for s in license_strings(c):
            low = s.lower()
            if any(frag in low for frag in DENY_LICENSE_FRAGMENTS):
                violations.append(
                    f"  {c.get('name','?')}@{c.get('version','?')} — {s}"
                )
                break
    if violations:
        sys.stderr.write(
            "\nERROR: Components with licenses incompatible with the\n"
            "GPL-2.0-or-later distribution of Phoenix were found:\n\n"
            + "\n".join(violations)
            + "\n\nRemove or replace these dependencies before continuing.\n"
        )
        sys.exit(3)


def render_markdown(sbom: dict) -> str:
    """Build LICENSE-3rd-Party.md from the merged SBOM + intro header."""
    if HEADER_MD_PATH.exists():
        header = HEADER_MD_PATH.read_text(encoding="utf-8").rstrip() + "\n\n"
    else:
        header = "# Third-Party Licenses\n\n"

    lines = [header]
    lines.append("## Components\n\n")
    lines.append("Generated from `sbom.cdx.json` (CycloneDX 1.6).\n\n")
    lines.append("| Name | Version | License | Source |\n")
    lines.append("|---|---|---|---|\n")

    for c in sbom.get("components", []):
        name = c.get("name", "—")
        version = c.get("version", "—")
        licenses = list(license_strings(c)) or ["—"]
        license_cell = " / ".join(licenses)

        url = ""
        for ref in c.get("externalReferences", []) or []:
            if ref.get("type") in ("website", "homepage", "vcs", "distribution"):
                url = ref.get("url", "")
                if url:
                    break
        src_cell = f"[link]({url})" if url else "—"

        # Markdown-escape pipes inside cells
        def _esc(s):
            return str(s).replace("|", r"\|")

        lines.append(
            f"| {_esc(name)} | {_esc(version)} | {_esc(license_cell)} | {src_cell} |\n"
        )

    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Generate to a tempfile and diff against the committed files. "
            "Exit 1 if either is stale. Used by CI."
        ),
    )
    args = parser.parse_args()

    print("→ Running cyclonedx-py against the current Python environment …")
    sbom = run_cyclonedx()
    print(f"  found {len(sbom.get('components', []))} Python components")

    print(f"→ Merging bundled components from {BUNDLED_JSON_PATH.name} …")
    sbom = merge_bundled(sbom)
    print(f"  total {len(sbom.get('components', []))} components after merge")

    print("→ Enforcing license deny-list …")
    enforce_policy(sbom)
    print("  ok — no denied licenses found")

    sbom_text = json.dumps(sbom, indent=2, sort_keys=False) + "\n"
    md_text = render_markdown(sbom)

    if args.check:
        ok = True
        for path, want in ((SBOM_PATH, sbom_text), (LICENSE_MD_PATH, md_text)):
            actual = path.read_text(encoding="utf-8") if path.exists() else ""
            if actual != want:
                sys.stderr.write(
                    f"ERROR: {path.relative_to(REPO_ROOT)} is out of date.\n"
                    f"       Regenerate locally with:\n"
                    f"         ./scripts/sbom/run.sh\n"
                    f"       then commit.\n"
                )
                ok = False
        if ok:
            print("✓ sbom.cdx.json and LICENSE-3rd-Party.md are up to date.")
        return 0 if ok else 1

    SBOM_PATH.write_text(sbom_text, encoding="utf-8")
    LICENSE_MD_PATH.write_text(md_text, encoding="utf-8")
    print(f"✓ Wrote {SBOM_PATH.relative_to(REPO_ROOT)} "
          f"({SBOM_PATH.stat().st_size:,} bytes)")
    print(f"✓ Wrote {LICENSE_MD_PATH.relative_to(REPO_ROOT)} "
          f"({sum(1 for _ in md_text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
