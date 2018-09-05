from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .context import CertificateContext
from .logging import log
from .utils import Hooks


class AuthBase:

    def __init__(self, acme_client: client.ClientV2, hooks: Hooks):
        self.acme_client = acme_client
        self.hooks = hooks

    def authorize(self, csr: x509.CertificateSigningRequest, context: CertificateContext) -> messages.OrderResource:
        raise NotImplementedError()


class NoAuth(AuthBase):

    def authorize(self, csr: x509.CertificateSigningRequest, context: CertificateContext) -> messages.OrderResource:
        order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))  # type: messages.OrderResource
        for authorization_resource in order.authorizations:  # type: messages.AuthorizationResource
            status = authorization_resource.body.status
            domain_name = authorization_resource.body.identifier.value
            if status != messages.STATUS_VALID:
                log.raise_error('Domain "%s" not authorized and auth disabled (status: %s)', domain_name, status)
        return order
