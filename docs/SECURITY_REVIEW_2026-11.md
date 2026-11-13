# Security review — November 2026 hardening sweep

Six parallel subsystem reviews (OIDC/auth, VPN stack, agent/packages,
updates chain, Matrix chat, core+antivirus) followed by an implementation
pass. Every claim below was verified against the code before being acted
on. Fixed items landed on `hardening/fable-sweep`; the full unit suite
(1841 tests) is green on macOS.

## Fixed in this sweep

| Sev | Subsystem | Finding | Commit |
|-----|-----------|---------|--------|
| HIGH | VPN/Windows | Pre-planted ProgramData IPC token granted any local user SYSTEM-service control → token regenerated per service start, exclusive-create, ACL-before-write | `9360a25` |
| HIGH | VPN/Windows | IPC port hijackable (SO_REUSEADDR, no exclusivity) → SO_EXCLUSIVEADDRUSE, no REUSEADDR | `9360a25` |
| HIGH | Agent/macOS | Client key traced into world-readable /tmp log via `set -x` → umask 077, xtrace off around key handling, log deleted on success | `a54b768` |
| HIGH | Agent/macOS | Root followed pre-plantable /tmp symlinks (status/log/agent-auth) → symlink+ownership refusal, mktemp+rename, root-owned workdir | `a54b768` |
| HIGH | Antivirus/macOS | Root clamd/freshclam consumed console-user-owned configs (OnUpdateExecute/VirusEvent → root exec); DB dir 775:staff → configs root:wheel 0644, DB root 0755 | `56e43c8` |
| HIGH | Antivirus/macOS | Root wrote through pre-plantable /tmp symlinks in postinstall → umask 077, refusal checks, mktemp+verified rename | `56e43c8` |
| HIGH | OIDC | Unsynchronized concurrent refresh raced the single-use rotating refresh token; loser could revoke the whole session → module lock + post-acquire freshness re-check | `f2de0e3` |
| MED | VPN/Windows | Script-hook "refusal" logged but still installed the config (two bypass paths) → hard-fail on every path | `9360a25` |
| MED | VPN/Win+Linux | Verify-then-use TOCTOU on configs → single in-memory read feeds both scan and privileged copy; Linux root commands source a vetted private 0600 copy | `9360a25` |
| MED | VPN/Windows | `_validated_config_path` accepted UNC/arbitrary paths (SYSTEM NTLM leak) → confined to known config dirs, UNC rejected | `9360a25` |
| MED | Agent/macOS | Client key in `security -w` argv (ps-visible) → piped via `security -i` stdin | `a54b768` |
| MED | Agent/macOS | Root executed user-swappable /tmp script copies (wazuh + clamav installers) → elevated command copies from the signed bundle into root-owned mktemp itself | `56e43c8`, `e0e4335` |
| MED | Agent/all | Client-key backups restored by root/SYSTEM without re-validation → key-line pattern check (512 B cap) before any restore | `a54b768` |
| MED | Chat | Assistant bubbles auto-opened any link scheme (file://, UNC) from bot-relayed attacker-influenced text → http/https whitelist | `fbcbd36` |
| MED | Chat | Room-content-derived error text rendered as trusted HTML → untrusted rendering | `fbcbd36` |
| MED | Chat | Plaintext room events accepted (homeserver-forgeable sender for bot replies/SIEM alerts) → Megolm-decrypted events only | `fbcbd36` |
| MED | OIDC | Refresh rejection left dead tokens claiming a live session → tokens cleared atomically on definitive rejection | `f2de0e3` |
| MED | OIDC | Non-atomic 3-write token store could pair new access with rotated-out refresh token → single-write `set_many` (secrets stay Fernet-encrypted) | `f2de0e3` |
| MED | Settings | Windows settings files written without ACL restriction → `_restrict_file_permissions` after every write | `f2de0e3` |
| MED | Updates | Version compare collapsed any suffixed version to 0 (downgrade enabler) → per-segment parse + tests | `dd8ccde` |
| MED | Store | Missing published sha256 silently installed unverified remote code → hard refusal; downloads stream against 50 MB cap | `dd8ccde` |
| MED | Agent | `PHOENIX_PACKAGES_URL` override could send the Bearer token over http/anywhere → https-only | `a54b768` |
| MED | Chat | Full assistant replies logged at INFO (quotes SIEM data) → DEBUG | `fbcbd36` |
| LOW | VPN | provisioning requests follow redirects with Bearer → `allow_redirects=False` | `9360a25` |
| LOW | Trace | Secret masking leaked 6-char prefixes → fixed-form `<redacted:len=N>` | `dd8ccde` |
| LOW | Chat | Unbounded turn growth (O(n²) re-render, multi-MB history) → 2 MiB / 500-part caps | `fbcbd36` |
| LOW | OIDC | Tokens minted then dropped unrevoked when login failed mid-way → best-effort revocation | `f2de0e3` |
| BUG | Agent/macOS | `full_install()` module-shadowing made the whole path UnboundLocalError-dead and skipped enrolled-identity bookkeeping | `a54b768` |

## Deferred — known, accepted for now, revisit before GA

1. **VPN/Windows M3**: move IPC from token-file TCP to a named pipe with an
   explicit DACL (or challenge-response) — the stronger fix behind H1/H2.
   Also: the service-created token file is not readable by the interactive
   user (machine-account grant), so a non-admin GUI cannot authenticate;
   resolve together with the named-pipe move. Do NOT "fix" by granting
   Users read.
2. **Chat B2**: bot device keys are not pinned (`ignore_unverified_devices=True`
   outbound) — the homeserver can attach a rogue device to the bot account
   and read user prompts. TOFU-pin the bot's device keys and alert on change.
3. **Chat B3**: adopted DM rooms aren't checked for extra members; require
   membership == {user, bot}.
4. **Updates (latent — updater currently hard-disabled, fails closed)**:
   appcast metadata unsigned → replay/downgrade of validly-signed old
   releases possible when re-enabled; wire channel.py-style highest-build
   rollback protection into the install paths. RPMs are unsigned
   (`gpgcheck=0`) — sign them. Windows `_run_installer` has a verify-then-exec
   window in %TEMP%. Pin `SUFeedURL`/`SUPublicEDKey` in the signed Info.plist
   when enabling Sparkle.
5. **Build pipeline**: repo indexes generated in unpinned Docker images and
   blind-signed on the host — pin images by digest and re-verify checksums
   before signing. `build-windows-vm.sh` uses `StrictHostKeyChecking=no`.
6. **Sysmon config** fetched from SwiftOnSecurity GitHub with no integrity
   check, applied elevated — bundle it or pin its sha256.
7. **Telemetry**: OTLP endpoint is `http://` (telemetry currently disabled);
   require https before ever enabling. Other INFO logs still carry metadata.
8. **OIDC low-priority**: loopback callback accepts any first GET (DoS of a
   pending login — random path segment would fix); RFC 9207 `iss` check;
   `validate_session` fail-open on network error is unbounded by design;
   legacy OTP module (`plugins/login/api.py`) is dead code — remove.
9. **ClamAV status file** parsed with trust from /tmp (same-uid only — no
   privilege boundary crossed; resolved for the writer side already).
10. **libolm/vodozemac**: chat E2EE bundles matrix-nio with vodozemac —
    confirm no libolm fallback ships in the frozen builds.

## Follow-up — 2026-11-13: new surfaces since the sweep, and their guards

| Surface | Guard | Tests |
|---------|-------|-------|
| Diagnostics export to the clipboard (`utils/diagnostics.py`) | `redact()`: http_trace masks + `PrivateKey =`/bearer/`ENC:` values, WireGuard-key, recovery-key and long-blob shapes; nothing read from the secret store | `tests/unit/test_diagnostics.py` |
| Job store `jobs.json` and codes in chat (`utils/jobs.py`) | 0600, exclusive-create temp + `os.replace`; a code attaches local details to that turn only; the answer is rendered untrusted | `test_jobs.py`, `test_chat_plugin.py::TestJobCodes` |
| Weekly sentence posted to the SIEM DM | counts and tile names only; the bot reads reactions only; the listener keeps the bot's messages only, so the post never returns as an alert | `test_chat_matrix_transport.py::TestPostToAlertsRoom` |
| Daily alert digest | view only; critical/high always on their own row; the store is untouched; digest lines are counts and host names as plain text | `test_dashboard_digest.py`, `test_alerts_plugin.py` |
| Undo of a job (`BasePlugin.undo`) | closed set per plugin, argument re-validated, same privileged path as the forward action, never the identity wipe; only the newest done job of a kind | `test_plugin_undo.py` |
| "Fix all" (`utils/fixes.py`) | a queue of the plugins' own actions, ids without arguments, no composed command; `gate()` drops fixes about other hosts; agent install and antivirus setup excluded | `test_fixes.py`, `test_plugin_fixes.py` |

