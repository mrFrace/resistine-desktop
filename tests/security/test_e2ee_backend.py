"""Chat E2EE must use vodozemac, never libolm.

libolm is deprecated and unmaintained upstream; matrix-nio prefers vodozemac
but will fall back to python-olm when it is importable. A build that happened
to carry python-olm would silently run user chat on the deprecated backend, so
this pins the property rather than trusting the lockfile.
"""

import importlib.util

import pytest


@pytest.mark.security
def test_vodozemac_is_available():
    """The supported Megolm backend must be installed."""
    assert importlib.util.find_spec("vodozemac") is not None, (
        "vodozemac is missing — matrix-nio would fall back to libolm or fail"
    )


@pytest.mark.security
def test_libolm_is_not_installed():
    """python-olm must not be importable, so no fallback can be selected."""
    spec = importlib.util.find_spec("olm")
    assert spec is None, (
        f"python-olm (libolm) is installed at {spec.origin!r}. Chat E2EE must "
        "run on vodozemac; remove python-olm from the environment and from any "
        "frozen build."
    )


class TestChatCaBundle:
    """The chat TLS bundle trusts the two Cloudflare Origin roots and nothing else.

    That bundle is what plugins/chat/main.py hands httpx as ``verify``: every
    root in it can issue a certificate the app accepts for the chat endpoint,
    so whoever holds the key of an extra root could terminate that connection.
    An internal root was pinned there until 2026-11-17 and must not come back.
    """

    def _subjects(self):
        """Subjects of the certs actually trusted by the bundle.

        Parsed, not grepped: a comment trusts nothing. Parsed in-process
        rather than through openssl because conftest stubs subprocess.
        """
        import os
        from cryptography import x509
        from utils.functions import get_resource_path
        path = get_resource_path(os.path.join("resources", "certs", "chat-ca-bundle.pem"))
        with open(path, "rb") as fh:
            pem = fh.read()
        return [c.subject.rfc4514_string() for c in x509.load_pem_x509_certificates(pem)]

    def test_only_the_cloudflare_origin_roots_are_trusted(self):
        subjects = self._subjects()
        assert len(subjects) == 2, subjects
        assert all("CloudFlare" in s for s in subjects), subjects

    def test_no_other_ca_file_ships(self):
        import os
        from utils.functions import get_resource_path
        certs_dir = get_resource_path(os.path.join("resources", "certs"))
        assert sorted(os.listdir(certs_dir)) == ["chat-ca-bundle.pem"]
