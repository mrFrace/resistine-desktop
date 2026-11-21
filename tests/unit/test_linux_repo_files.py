"""The rpm repository files the package installs check package signatures.

Signed metadata alone binds the packages by checksum; the per-package check
is the second lock, and it only holds while the publish script keeps signing
every rpm it serves.
"""
import configparser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / "packaging" / "linux" / "repo"


def _section(name):
    parser = configparser.ConfigParser()
    parser.read_string((REPO / name).read_text())
    return parser["phoenix"]


@pytest.mark.unit
@pytest.mark.parametrize("name, flag", [
    ("phoenix.repo", "gpgcheck"),
    ("phoenix-zypp.repo", "pkg_gpgcheck"),
])
def test_rpm_repo_checks_metadata_and_packages(name, flag):
    repo = _section(name)
    assert repo[flag] == "1"
    assert repo["repo_gpgcheck"] == "1"
    assert repo["gpgkey"] == "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-phoenix"
    assert repo["baseurl"].startswith("https://")


@pytest.mark.unit
def test_publish_signs_and_verifies_every_rpm():
    script = (ROOT / "scripts" / "build" / "publish-linux-repos.sh").read_text()
    assert "--addsign" in script
    assert "--checksig" in script


@pytest.mark.unit
def test_post_turns_the_check_on_in_an_older_zypper_copy():
    spec = (ROOT / "packaging" / "linux" / "phoenix.spec.in").read_text()
    assert "s/^pkg_gpgcheck=0$/pkg_gpgcheck=1/" in spec
