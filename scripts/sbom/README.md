# SBOM Tooling

This folder generates Resistine's Software Bill of Materials (SBOM) and the
human-readable license attribution document derived from it.

## Outputs (committed at the repo root)

- **`sbom.cdx.json`** — CycloneDX 1.6 JSON. Machine-readable. Consumed by
  Dependency-Track, Snyk, OWASP DT, procurement reviews, etc.
- **`LICENSE-3rd-Party.md`** — Markdown table rendered from the SBOM.
  Shipped inside the installer next to `LICENSE.md` on both macOS
  (`Contents/Resources/`) and Windows (`{app}\`).

Both files are intentionally checked in. The CI release workflow regenerates
them and rejects the build if either is stale.

## Regenerate

```bash
./scripts/sbom/run.sh
git add sbom.cdx.json LICENSE-3rd-Party.md
git commit -m "chore: regenerate SBOM"
```

That's it. The wrapper builds (and caches) a clean production virtual
environment at `.sbom-venv/`, installs `requirements-{platform}.txt` plus
`cyclonedx-bom`, then runs `generate_sbom.py`. The cached venv survives
subsequent runs so repeat regenerations take a few seconds.

### Variants

| Command | What it does |
|---|---|
| `./scripts/sbom/run.sh` | Regenerate both artifacts |
| `./scripts/sbom/run.sh --check` | CI mode — exit 1 if committed files are stale |
| `./scripts/sbom/run.sh --rebuild-venv` | Delete `.sbom-venv/` and start over |

## Files in this folder

| File | Role | Edit by hand? |
|---|---|---|
| `run.sh` | One-command wrapper. Manages the clean prod venv. | No |
| `generate_sbom.py` | Python orchestrator. Runs cyclonedx-py, merges bundled components, enforces license policy, renders Markdown. | No (unless changing the generator itself) |
| `sbom-bundled.json` | Hand-maintained CycloneDX components for non-Python software (ClamAV, WireGuard, Wazuh Agent, `resistine-vpn-cli`). | **Yes** — when a bundled binary's version, source, or license changes |
| `license-3rd-party-header.md` | Intro text prepended to `LICENSE-3rd-Party.md`. | **Yes** — for wording changes |

## Why this design

### Why CycloneDX

It's the de-facto SBOM format for Python. `cyclonedx-bom` is OWASP-maintained,
and the 1.6 spec includes everything procurement and SCA tooling expect:
PURLs, license expressions, dependency edges, component hashes, external
references. SPDX is the alternative but is less idiomatic for Python and
has more verbose output for the same content.

### Why a clean venv wrapper

`cyclonedx-py environment` walks whatever Python env is active. If you run
it from `.venv/` (which has pytest, black, pytest-mock, etc.), those leak
into the SBOM. That's wrong — they don't ship to users, and CI runs the
generator in a prod-only env so committed vs CI-generated files would
disagree. The freshness gate would fail every time. The wrapper solves
this by always running in `.sbom-venv/`.

### Why commit the SBOM

Compliance reviewers want a stable URL to point at, and dependency churn is
worth seeing in `git log` / PR diffs. The file is ~350 KB JSON — small
enough to be reasonable in a Git repo, large enough that we don't lose
information by storing it. Output is deterministic (`--output-reproducible`)
so diffs are real signal, not timestamp noise.

### License deny-list

`generate_sbom.py` aborts the build if any component (Python or bundled)
ships under AGPL, SSPL, BUSL, or Commons Clause. These are one-way
compatible licenses (or not OSS at all) and can't be combined with our
GPL-2.0-or-later distribution. If a new pip dep brings one in, the build
fails right here rather than silently shipping an incompatible license.

## CI integration

`.github/workflows/release.yml` calls `python scripts/sbom/generate_sbom.py`
directly (CI already provisions a clean venv per job, so the wrapper isn't
needed there). It then runs `git diff --exit-code` to verify the committed
files match, and uploads `sbom.cdx.json` as a release artifact with 90-day
retention.
