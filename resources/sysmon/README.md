# Sysmon configuration

`sysmonconfig-export.xml` is the SwiftOnSecurity sysmon-config
(<https://github.com/SwiftOnSecurity/sysmon-config>, source version 74,
2021-07-08), licensed Creative Commons Attribution 4.0. It is bundled here so
the Windows Endpoint agent install applies a known file instead of fetching
`master` from GitHub at install time and running it elevated.

`plugins/wazuh/config.py:WINDOWS_SYSMON_CONFIG_SHA256` pins its SHA-256; the
installer refuses the file when the hash differs. To update: replace the file,
recompute `sha256sum resources/sysmon/sysmonconfig-export.xml`, update the
constant and the version line above.
