# Sysmon configuration

`sysmonconfig-export.xml` is the SwiftOnSecurity sysmon-config
(<https://github.com/SwiftOnSecurity/sysmon-config>, source version 74,
2021-07-08), licensed Creative Commons Attribution 4.0. It is bundled here so
the Windows Endpoint agent install applies a known file instead of fetching
`master` from GitHub at install time and running it elevated.

`plugins/wazuh/config.py:WINDOWS_SYSMON_CONFIG_SHA256` pins its SHA-256; the
installer refuses the file when the hash differs. The file is kept with LF
line endings (`.gitattributes` forces LF on every checkout, so the bytes on
disk are the committed bytes on every platform); upstream ships CRLF. To
update: replace the file, convert it to LF, recompute
`sha256sum resources/sysmon/sysmonconfig-export.xml`, update the constant and
the version line above.
