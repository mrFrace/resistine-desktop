"""Linux agent package choice: .deb for Debian/Ubuntu, .rpm for Fedora/RHEL/openSUSE."""

from unittest.mock import patch

import pytest

from plugins.wazuh.agent import wazuh_functions_linux as w


@pytest.mark.parametrize("family,plat", [
    ("deb", "linux-amd64"), ("rpm", "linux-amd64-rpm"), ("arch", None), (None, None)])
def test_package_platform_by_family(family, plat):
    with patch.object(w.phoenix_packages, "platform_key", return_value="linux-amd64"), \
            patch.object(w, "_get_os_info", return_value=family):
        assert w.package_platform() == plat


def test_no_package_off_amd64():
    with patch.object(w.phoenix_packages, "platform_key", return_value=None), \
            patch.object(w, "_get_os_info", return_value="rpm"):
        assert w.package_platform() is None
        assert w.get_package_url() is None


def test_rpm_manifest_url():
    with patch.object(w.phoenix_packages, "platform_key", return_value="linux-amd64"), \
            patch.object(w, "_get_os_info", return_value="rpm"):
        assert w.get_package_url().endswith("/packages/linux-amd64-rpm/current/manifest.json")


def test_download_asks_for_the_rpm(tmp_path):
    with patch.object(w, "package_platform", return_value="linux-amd64-rpm"), \
            patch.object(w.phoenix_packages, "download_or_none", return_value="/x.rpm") as dl:
        assert w.download_package() == "/x.rpm"
    assert dl.call_args.kwargs["plat"] == "linux-amd64-rpm"


@pytest.mark.parametrize("tool,expected", [
    ("dnf", "dnf -y install --nogpgcheck '/t/a.rpm'"),
    ("zypper", "zypper --non-interactive install --allow-unsigned-rpm '/t/a.rpm'"),
    ("yum", "yum -y install --nogpgcheck '/t/a.rpm'"),
    (None, "rpm -Uvh '/t/a.rpm'"),
])
def test_rpm_install_uses_the_package_manager(tool, expected):
    with patch.object(w.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n == tool else None):
        assert w._rpm_install_cmd("ENV=1", "/t/a.rpm") == f"ENV=1 {expected}"


_CONF = """<ossec_config>
  <agent>
    <manager>
      <endpoint>MANAGER_IP</endpoint>
    </manager>
    <enrollment>
      <enabled>yes</enabled>
    </enrollment>
  </agent>
  <wodle name="syscollector">
    <groups>yes</groups>
  </wodle>
</ossec_config>
"""


def test_enrollment_group_leaves_other_groups_tags(tmp_path, allow_subprocess):
    """Only <enrollment>'s <groups> changes; syscollector's stays 'yes', and
    a MANAGER_IP placeholder left by a failed package script is filled in."""
    import subprocess

    conf = tmp_path / "ossec.conf"
    conf.write_text(_CONF)
    subprocess.run(["sh", "-c", w._set_ossec_enrollment(str(conf), "host-1", "u_test")], check=True)
    subprocess.run(["sh", "-c", w._set_ossec_enrollment(str(conf), "host-1", "u_other")], check=True)
    out = conf.read_text()
    assert "<groups>yes</groups>" in out
    assert out.count("<groups>u_other</groups>") == 1 and "u_test" not in out
    assert "<agent_name>host-1</agent_name>" in out
    assert "<endpoint>dashboard.phoenix.exposed:1517</endpoint>" in out
