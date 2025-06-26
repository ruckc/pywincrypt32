import pytest
import pywincrypt32

# These tests require access to the Windows certificate store.
# They will be skipped if not running on Windows.
import platform

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows", reason="Requires Windows certificate store"
)


def test_list_certificates_returns_references():
    certs = pywincrypt32.list_certificates("MY")
    assert isinstance(certs, list)
    if certs:
        for cert in certs:
            print(f"Found certificate: {cert}")
    else:
        pytest.skip("No certificates in store")


def test_with_certificate_context_manager():
    certs = pywincrypt32.list_certificates("MY")
    if not certs:
        pytest.skip("No certificates in store")
    thumbprint = certs[0].thumbprint
    with pywincrypt32.with_certificate("MY", thumbprint) as p_ctx:
        assert p_ctx is not None
        # Optionally, check that p_ctx is a ctypes pointer
        import ctypes
        from pywincrypt32 import CERT_CONTEXT

        assert isinstance(p_ctx, ctypes.POINTER(CERT_CONTEXT))
