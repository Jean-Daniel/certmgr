from acme import client, messages
from cryptography import x509

from .hook import authorize_hook
from .http import authorize_http
from .noop import authorize_noop
from ..config import AuthType
from ..context import CertificateContext
from ..utils import Hooks


def authorize(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    auth = context.config.auth
    if auth.type == AuthType.noop:
        return authorize_noop(csr, acme_client, hooks)
    elif auth.type == AuthType.http:
        return authorize_http(csr, context, acme_client, hooks)
    elif auth.type == AuthType.dns:
        from .dns import authorize_dns
        return authorize_dns(csr, context, acme_client, hooks)
    elif auth.type == AuthType.hook:
        return authorize_hook(csr, context, acme_client, hooks)
