# Release keys: backup, rotation, compromise

The app trusts a desktop release because its manifest is signed with a
minisign key pinned in `plugins/wazuh/agent/phoenix_packages.py`:

- `DESKTOP_MINISIGN_PUBLIC_KEY`: the release key. Secret half:
  `~/.config/phoenix-release/desktop-minisign.key` on the release machine,
  password-protected, used by `scripts/build/publish-desktop.sh`.
- `DESKTOP_MINISIGN_BACKUP_PUBLIC_KEYS`: backup keys. A release signed with
  any of them is accepted the same way. One is pinned: key id
  `6D13747A8A9A1783` (2026-11-21). It protects only installs running a
  build made after that date; for older installs, losing the release key
  still means they cannot be updated through the channel.

A build only knows the keys it was shipped with. Everything below works
through that: a key can sign for an install only after a build pinning it
has reached that install.

The agent package key (`MINISIGN_PUBLIC_KEY`, CI variable) and the Linux
repository OpenPGP key are separate and not covered here.

The same keys sign the Store's plugin catalog (`optional_plugins.json`,
`scripts/build/sign-plugin-catalog.sh`, checked by
`plugins/plugin_catalog.py`). Whoever holds a release key can therefore
also choose which plugins the Store installs: after a rotation or a theft,
sign the catalog again with the new key and treat the old catalog like an
old release.

## Create the backup key (once, now)

On a machine that is not the release machine and not a server:

```sh
minisign -G -p phoenix-desktop-backup.pub -s phoenix-desktop-backup.key
```

1. Choose a password different from the release key's.
2. Put `phoenix-desktop-backup.key` on two offline media kept in two places
   (for example two USB sticks; minisign keys cannot live on a hardware
   token). Keep the password somewhere else. Delete the file from the
   machine it was made on.
3. Add the second line of `phoenix-desktop-backup.pub` to
   `DESKTOP_MINISIGN_BACKUP_PUBLIC_KEYS`, with its key id in a comment.
4. Add the same public key to the server's `phoenix-packages-promote`
   (server flake, `modules/services/phoenix-packages.nix`): it verifies the
   signature too and would refuse a backup-signed release otherwise.
5. Ship a release. From that build on, installs accept the backup key.

`tests/unit/test_update_channel.py` checks the pinned keys are well-formed
and have distinct key ids.

## Keeping the channel fresh

A release is signed for 45 days (`PHOENIX_EXPIRES_DAYS`); after that the
app tells users the update channel is stale. When no new build goes out,
run `./scripts/build/publish-desktop.sh --renew` before the date: it signs
the last published manifest again with a new expiry and uploads only that.
The server takes it for the current release when nothing else changed
(server flake, see `plans/update-security-server-renewal.patch`).

## Planned rotation (new release key, nothing went wrong)

1. Generate the new key. Pin it as a backup key, add it to the server.
2. Ship at least one release signed with the **old** key, and wait until
   installs have picked it up (the app checks daily; give it weeks, and
   remember installs that are rarely started).
3. Make the new key `DESKTOP_MINISIGN_PUBLIC_KEY`; move the old one to the
   backup list or drop it. Sign with the new key from here on
   (`PHOENIX_DESKTOP_KEY=...`).
4. Installs that never got the release from step 2 cannot verify releases
   any more: they must reinstall from the website.

## The release key is lost (disk died, password forgotten)

1. Take the backup key out of storage. Sign the next release with it:
   `PHOENIX_DESKTOP_KEY=/path/phoenix-desktop-backup.key ./scripts/build/publish-desktop.sh ...`
2. In that same release: generate a new release key, make it
   `DESKTOP_MINISIGN_PUBLIC_KEY`, remove the lost key, and pin a fresh
   backup key (the old backup key has now been on a connected machine;
   keep it listed for one more release, then drop it).
3. Update the server's key list to match.

## The release key is stolen or may have been copied

The thief can sign a manifest every current install accepts. To use it
they also need to answer for `auth.phoenix.exposed` (the server, the CDN
account, or a position in the victim's network with a certificate the
victim trusts). Assume they can.

1. Stop publishing with the stolen key.
2. Build a release that removes the stolen key from the app, with a new
   release key and a new backup key pinned. Sign it with the **backup**
   key. Give it a build ID above anything the thief could have published.
3. Remove the stolen key from the server's key list first, then publish.
4. Tell users to update now. An install is exposed until it runs a build
   without the stolen key; nothing can revoke a key inside a build that is
   already installed.
5. Check what the server served while the key was exposed (the package
   store's logs, `current/` history).

If the backup key is stolen instead: ship a release, signed with the
release key, that drops it and pins a new one.

## Not possible, by design

- Revoking a key remotely. There is no revocation list: a list would need
  its own signing key and the same problem.
- Signing with a key no shipped build pins. If both keys are lost, existing
  installs must reinstall by hand.
