from typing import TypeVar, Union

from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .dns import authorize_dns
from .hook import authorize_hook
from .http import authorize_http
from .noop import authorize_noop
from ..config import AuthDef, AuthType
from ..utils import Hooks

T = TypeVar('T', bound=AuthDef)


def authorize(csr: Union[x509.CertificateSigningRequest, bytes], auth: T, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    if isinstance(csr, x509.CertificateSigningRequest):
        csr = csr.public_bytes(serialization.Encoding.PEM)

    if auth.type == AuthType.noop:
        return authorize_noop(csr, acme_client, hooks)
    elif auth.type == AuthType.http:
        return authorize_http(csr, auth, acme_client, hooks)
    elif auth.type == AuthType.dns:
        return authorize_dns(csr, auth, acme_client, hooks)
    elif auth.type == AuthType.hook:
        return authorize_hook(csr, auth, acme_client, hooks)
