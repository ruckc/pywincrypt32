import ctypes
from ctypes import wintypes
from contextlib import contextmanager

# Constants
CERT_STORE_PROV_SYSTEM = 10
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000


# Structures
class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", wintypes.LPBYTE),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", wintypes.LPVOID),
        ("hCertStore", wintypes.HANDLE),
    ]


# Load libraries
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

# Function prototypes
crypt32.CertOpenStore.restype = wintypes.HANDLE
crypt32.CertOpenStore.argtypes = [
    wintypes.LPCSTR,
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPCWSTR,
]
crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(CERT_CONTEXT)
crypt32.CertEnumCertificatesInStore.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CERT_CONTEXT),
]
crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(CERT_CONTEXT)]
crypt32.CertCloseStore.restype = wintypes.BOOL
crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]


def get_cert_subject(p_ctx):
    """
    Extracts the subject from a CERT_CONTEXT pointer using CertGetNameStringW.
    """
    CertGetNameStringW = crypt32.CertGetNameStringW
    CertGetNameStringW.restype = wintypes.DWORD
    CertGetNameStringW.argtypes = [
        ctypes.POINTER(CERT_CONTEXT),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
    buf = ctypes.create_unicode_buffer(256)
    CertGetNameStringW(p_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256)
    return buf.value


def get_cert_issuer(p_ctx):
    """
    Extracts the issuer from a CERT_CONTEXT pointer using CertGetNameStringW.
    """
    CertGetNameStringW = crypt32.CertGetNameStringW
    CertGetNameStringW.restype = wintypes.DWORD
    CertGetNameStringW.argtypes = [
        ctypes.POINTER(CERT_CONTEXT),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
    buf = ctypes.create_unicode_buffer(256)
    CertGetNameStringW(p_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256)
    return buf.value


class CertificateReference:
    """
    Represents a reference to a certificate with its subject and thumbprint.
    """

    def __init__(self, subject: str, thumbprint: str, issuer: str):
        self.subject = subject
        self.thumbprint = thumbprint
        self.issuer = issuer

    def __repr__(self):
        return f"CertificateReference(subject={self.subject}, thumbprint={self.thumbprint}, issuer={self.issuer})"


def list_certificates(
    store_name, store_location="CURRENT_USER"
) -> list[CertificateReference]:
    """
    Returns a list of dicts with 'subject' and 'thumbprint' for each certificate in the store.
    """
    if store_location == "CURRENT_USER":
        store_flag = CERT_SYSTEM_STORE_CURRENT_USER
    else:
        store_flag = CERT_SYSTEM_STORE_LOCAL_MACHINE
    h_store = crypt32.CertOpenStore(b"System", 0, 0, store_flag, store_name)
    if not h_store:
        raise OSError("Failed to open certificate store")
    certs: list[CertificateReference] = []
    p_ctx = None
    try:
        while True:
            p_ctx = crypt32.CertEnumCertificatesInStore(h_store, p_ctx)
            if not p_ctx:
                break
            encoded = ctypes.string_at(
                p_ctx.contents.pbCertEncoded, p_ctx.contents.cbCertEncoded
            )
            import hashlib

            thumbprint = hashlib.sha1(encoded).hexdigest().upper()
            # Use direct call to local get_cert_subject
            subject = get_cert_subject(p_ctx)
            issuer = get_cert_issuer(p_ctx)
            certs.append(CertificateReference(subject, thumbprint, issuer))
    finally:
        crypt32.CertCloseStore(h_store, 0)
    return certs


@contextmanager
def with_certificate(store_name, thumbprint, store_location="CURRENT_USER"):
    """
    Context manager that yields a CERT_CONTEXT pointer for the given thumbprint.
    Automatically closes the store and frees the CERT_CONTEXT.
    Usage:
        with with_certificate("MY", thumbprint) as p_ctx:
            ...
    """
    if store_location == "CURRENT_USER":
        store_flag = CERT_SYSTEM_STORE_CURRENT_USER
    else:
        store_flag = CERT_SYSTEM_STORE_LOCAL_MACHINE
    h_store = crypt32.CertOpenStore(b"System", 0, 0, store_flag, store_name)
    if not h_store:
        raise OSError("Failed to open certificate store")
    p_ctx = None
    try:
        while True:
            p_ctx = crypt32.CertEnumCertificatesInStore(h_store, p_ctx)
            if not p_ctx:
                break
            encoded = ctypes.string_at(
                p_ctx.contents.pbCertEncoded, p_ctx.contents.cbCertEncoded
            )
            import hashlib

            if hashlib.sha1(encoded).hexdigest().upper() == thumbprint.upper():
                try:
                    yield p_ctx
                finally:
                    crypt32.CertFreeCertificateContext(p_ctx)
                return
        raise ValueError(
            f"Certificate with thumbprint {thumbprint} not found in store {store_name}"
        )
    finally:
        crypt32.CertCloseStore(h_store, 0)
