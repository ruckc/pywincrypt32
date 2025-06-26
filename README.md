# pywincrypt32

`pywincrypt32` is a Python library for accessing and enumerating certificates in the Windows certificate store using ctypes. It allows you to list certificates and work with certificate contexts in a Pythonic way.

## Features

- List certificates in a Windows certificate store.
- Access certificate subject, issuer, and thumbprint.
- Context manager for working with certificate contexts.

## Requirements

- Python 3.13+
- Windows OS

## Installation

You can install `pywincrypt32` via pip:
```sh
pip install pywincrypt32
```
or using Poetry:
```sh
poetry add pywincrypt32
```

## Usage

### List Certificates

```python
import pywincrypt32

# List all certificates in the "MY" store for the current user
certs = pywincrypt32.list_certificates("MY")
for cert in certs:
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Thumbprint: {cert.thumbprint}")
    print("---")
```

### Use a Certificate Context

```python
import pywincrypt32

# Get the thumbprint of a certificate (e.g., the first one in the store)
certs = pywincrypt32.list_certificates("MY")
if certs:
    thumbprint = certs[0].thumbprint
    with pywincert.with_certificate("MY", thumbprint) as p_ctx:
        # Use p_ctx (a CERT_CONTEXT pointer) as needed
        print("Certificate context acquired!")
else:
    print("No certificates found in the store.")
```

## Testing

Run tests with:

```sh
poetry run pytest
```

## License

APACHE-2.0
