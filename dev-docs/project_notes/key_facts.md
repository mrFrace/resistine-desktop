# Key Facts

Important config, ports, quirks, and environment details worth remembering.

---

- **Python target:** 3.13
- **GUI framework:** CustomTkinter
- **Config location (macOS):** `~/Library/Application Support/Resistine`
- **Config location (Windows):** `%APPDATA%/Resistine`
- **Config location (Linux):** `~/.config/resistine`
- **Secrets encryption:** Fernet, master key in system keyring, encrypted values prefixed `ENC:`
- **Log rotation:** 10 MB max, compressed after 1 week
- **ClamAV communication:** Unix socket (PING/SCAN) + subprocess for `clamdscan`/`freshclam`
- **VPN artifacts:** Downloaded from `Resistine/resistine-vpn-macos` CI via `gh` CLI
- **ClamAV artifacts:** Downloaded from `Resistine/ClamAV-Mac` CI via `gh` CLI
- **Linting:** Trunk (ruff, black, isort, bandit, shellcheck, shfmt, markdownlint, prettier, trufflehog, checkov)
- **CI:** `python -m compileall` syntax check on push/PR (Python 3.13)
