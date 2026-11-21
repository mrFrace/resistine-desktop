# Desktop update security: review and hardening plan

Status (2026-11-21): review of the code on `main` plus a plan; nothing is
changed. Read from the repository only: the server side
(`phoenix-packages-promote`, the web host, Cloudflare settings) and the
release machine were not inspected.

## Question

Can someone in the middle pretend to be our server and hand a user an
update carrying their code?

## Short answer

- **The in-app update check cannot be forged.** It trusts a signature made
  with a key that is not on any server, not the connection.
- **On Linux the installed update cannot be forged either**: apt, dnf and
  pacman verify repository signatures made with an offline key.
- **On Windows it can.** The app only tells the user to download the new
  installer from `phoenix.exposed/apps` in a browser. Nothing checks that
  file against the signed manifest, and no Authenticode signing step
  exists in the build scripts. Whoever controls that download (the web
  host, the CDN account, a TLS-intercepting proxy) controls what gets
  installed. The same holds for the first install on every OS.
- macOS is covered by Developer ID signing and notarization, as long as
  the user does not override Gatekeeper.

So: not bulletproof. The check is solid; the Windows delivery is the gap.

## How updates work today

Sparkle/WinSparkle are off (`utils/updates/manager.py:
UPDATES_ENABLED = False`, `main.py` never calls `updates.init`). The
replacement is two separate mechanisms.

**1. The signed channel (`utils/updates/channel.py`,
`plugins/wazuh/agent/phoenix_packages.py`)**: answers "is there a newer
build". Settings → Check for updates fetches
`auth.phoenix.exposed/packages/desktop/current/manifest.json` and its
`.minisig` with the user's MAS token, verifies it, and shows a sentence
(`plugins/settings/main.py::update_check_text`). It downloads and installs
nothing.

**2. Delivery**:

| OS | How the new build arrives | Who verifies it |
|---|---|---|
| Linux deb | apt, repo `phoenix.exposed/linux/apt`, `Signed-By` keyring | apt, OpenPGP |
| Linux rpm | dnf/zypper, `repo_gpgcheck=1` | dnf, OpenPGP on metadata |
| Arch | pacman, `SigLevel = Required TrustedOnly` (user enables the repo by hand) | pacman |
| Windows | user downloads the `.exe` from the website | nobody |
| macOS | user downloads the `.dmg` from the website | Gatekeeper (Developer ID + notarization) |

## What holds

Checked in the code and pinned by `tests/unit/test_update_channel.py`:

- **Pinned key, not TLS.** The manifest must verify against
  `DESKTOP_MINISIGN_PUBLIC_KEY` compiled into the app. A forged
  certificate, a hostile CDN or a hijacked DNS record cannot produce a
  valid manifest.
- **The secret key is not on the server.** `publish-desktop.sh` signs on
  the release machine with a password-protected key; the server only
  verifies and promotes. A server compromise cannot sign a release.
- **Key separation.** Agent packages and desktop releases use different
  keys and different products in the signed content; each refuses the
  other's signature (tests cover both directions).
- **The signature covers the meaning.** The signed trusted comment is
  `phoenix-desktop <dir> <expires>` and must match the manifest; `dir`
  must end in the build number. A valid signature for one build cannot be
  relabelled as another.
- **Rollback.** A release below the highest build this machine has seen
  signed is refused; one at or below the running build is "no update".
- **Freeze.** Each release carries a signed expiry (90 days by default);
  past it the check says the channel may be holding releases back.
- **Hygiene.** HTTPS only, certificate verification on, redirects off,
  manifest capped at 64 KiB, every field allowlisted by regex, size capped.
- **Linux repositories.** Metadata is signed with an OpenPGP key kept on
  the release machine; the keyring ships inside the package. The web host
  cannot forge an update.
- **Legacy updater is inert.** No `SUFeedURL`, no `SUPublicEDKey`, and the
  backends are never initialised.

## Findings

### F1. Windows: the installer is delivered and run unverified (high)

The signed manifest lists the Windows installer's sha512, but the app never
downloads it and never compares anything. The user fetches the file with a
browser from `phoenix.exposed/apps`. No `signtool`/Authenticode step exists
in `scripts/build/` or `packaging/windows/`, so Windows cannot tell our
installer from another one either, and SmartScreen warns on both, which
trains users to click through.

Who can exploit it: anyone who can change that download: the web host, the
Cloudflare account in front of it, a rogue or corporate CA on the user's
machine, a compromised mirror. The installer runs elevated.

### F2. First install on every OS is trust-on-first-use over TLS (medium)

The first `.deb`/`.rpm` carries the repository keyring, and it is itself
downloaded from the website with nothing to check it against. A hostile
first download installs a hostile keyring, after which every "signed"
update verifies. No fingerprints or signatures are published for manual
verification.

### F3. Nobody is told about updates (medium)

The check runs only when the user clicks. No check at start, no
notification. Not a forgery risk, but users stay on vulnerable builds, and
the stale-channel warning (the freeze defence) is only ever seen by
someone who clicks.

### F4. One key, on one machine, with no rotation or revocation (medium)

The desktop minisign key and the repository OpenPGP key both live under
`~/.config/phoenix-release/` on the release machine, protected by a
password. The app pins exactly one key. If it leaks there is no way to
revoke it, and if it is lost there is no way to ship another update to
existing installs. No second pinned key, no documented procedure.

### F5. rpm repository leaves package signature checking off (low)

`packaging/linux/repo/phoenix.repo` has `gpgcheck=0`. Signed metadata with
checksums (`repo_gpgcheck=1`) already binds the packages, so this is not a
hole against a middleman, but `publish-linux-repos.sh` signs the rpms
precisely "so dnf can run with gpgcheck=1" and the repo file was never
switched. `phoenix-zypp.repo` likewise has `pkg_gpgcheck=0`.

### F6. Freeze window is up to 90 days and bound to the local clock (low)

Someone able to intercept the connection can replay the last valid
manifest and the app says "up to date" until that manifest's expiry. They
cannot install anything this way; they can only delay.

### F7. Legacy updater leftovers (low)

Still shipped or run although unused: `WinSparkle.dll`
(`packaging/Phoenix.spec:166`), `Sparkle.framework` (copied and signed by
`build-distribution.sh`), the "Sign DMG for Sparkle" step and
`SPARKLE_ED_PRIVATE_KEY` secret in `.github/workflows/release.yml`, and
`utils/updates/{appcast,darwin,windows,linux}.py`. Inert today; they are
attack surface and a trap for whoever flips `UPDATES_ENABLED` later.
CLAUDE.md also still describes the WinSparkle flags.

### F8. Plugins are hash-checked, not signed (medium, adjacent)

Store plugins are executable code. Their SHA-256 comes from
`optional_plugins.json` fetched over HTTPS from a GitHub repository, so
the hash and the archive share one trust root (that repository and TLS).
`plugin_manager.py` says so itself ("Until archives are signed"). The
minisign machinery above could cover this list too.

### Notes

- `PHOENIX_PACKAGES_URL` can redirect the check (and the MAS token) to
  another https host. It needs control of the user's environment and the
  signature check still applies; consider honouring it only in debug runs.
- `highest_build` lives in the user's settings file. A local attacker can
  reset it; a local attacker is outside this question.
- The agent installer path (`phoenix_packages.download`) does verify
  size and sha512 against its signed manifest before anything is
  installed. That is the model F1 should follow.

## Plan

| # | Change | Closes | Where |
|---|---|---|---|
| 1 | In-app verified download: fetch `desktop/<dir>/<file>` from the store, check size and sha512 against the signed manifest (reuse the agent `download()` flow), write to a fresh private directory, re-verify immediately before launch, then start the installer. Windows first; macOS can open the verified dmg. | F1 | `utils/updates/channel.py`, `phoenix_packages.py`, `plugins/settings/main.py`, tests in `test_update_channel.py` and `test_security_hardening.py` |
| 2 | Authenticode-sign the Windows installer and the app executables in the build; have the app check the signer of the file it is about to run as a second, independent check. | F1, F2 | `scripts/build/build-windows-installer.ps1`, `PhoenixInstaller.iss` (`SignTool=`) |
| 3 | Publish for every download on the website: the sha512, a `.minisig`, and the public keys with fingerprints, plus two lines on how to verify. | F2 | website, `publish-desktop.sh` |
| 4 | Check quietly after start and once a day (jittered, manual check stays); show an "update available" row and the stale warning without being asked. No silent install. | F3, F6 | `main.py`, `utils/updates/channel.py`, Dashboard/Settings |
| 5 | Pin a second, offline backup key in the app now (accept either); write the rotation and compromise procedure; move the active keys to a hardware token. | F4 | `phoenix_packages.py`, new section in this folder |
| 6 | Set `gpgcheck=1` (and `pkg_gpgcheck=1`) once every rpm in the repository is signed. | F5 | `packaging/linux/repo/*.repo` |
| 7 | Shorten the default expiry to 30 to 45 days and re-sign the current release on a schedule. | F6 | `publish-desktop.sh` (`PHOENIX_EXPIRES_DAYS`) |
| 8 | Remove WinSparkle, Sparkle.framework, the Sparkle signing step and secret, and the appcast backends; fix CLAUDE.md. | F7 | `Phoenix.spec`, `build-distribution.sh`, `release.yml`, `utils/updates/` |
| 9 | Sign `optional_plugins.json` with a pinned minisign key and verify it before trusting any hash in it. | F8 | `plugins/plugin_manager.py`, plugin repo |

Done on `autofixes`: 1 (`utils/updates/installer.py`, Settings → "Download
and install", Windows and macOS) and the code half of 2 (signing in
`build-windows-installer.ps1` and `PhoenixInstaller.iss`, signer check in
the app). Still open for 2: buying a code-signing certificate, making it
reachable from the build VM, setting `PHOENIX_SIGN_THUMBPRINT` and
`PHOENIX_REQUIRE_SIGNING=1` for releases, and then
`installer.WINDOWS_PUBLISHER`. Until then Windows builds stay unsigned and
the signer check is skipped. None of the Windows or macOS paths has been
run on a real machine.

Order: 1 and 2 first (they close the only path by which a middleman gets
code onto a machine), then 5 and 4, then the rest.

## To verify outside this repository

- That `phoenix-packages-promote` really refuses unsigned or lower builds
  (the script says so; the code is in the server flake).
- Whether the website's copy of each installer is byte-identical to the
  store's, and who can write to `/var/www/phoenix.exposed`.
- Whether any Windows signing happens outside the scripts in this repo.
- Cloudflare account protection (it terminates TLS for both hosts).
- Where the release keys are backed up.
