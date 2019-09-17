from typing import List

from acme import client, messages
from cryptography import x509

from .driver import AuthDriver
from ..config import HookAuthDef
from ..context import CertificateContext
from ..utils import Hooks


class HookAuthDriver(AuthDriver):

    def __init__(self, acme_client: client.ClientV2, auth: HookAuthDef, common_name: str):
        super().__init__(acme_client)
        self.auth = auth
        self.common_name = common_name

    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks):
        if self.auth.each_domain:
            for authzr in authzrs:
                domain_name = authzr.body.identifier.value
                # TODO: tweak argument list
                self.auth.cmd.execute(common_name=domain_name)
        else:
            self.auth.cmd.execute(common_name=self.common_name)
        return authzrs  # FIXME: should update authzrs


def authorize_hook(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    # don't bother extracting common name from CSR as we already have it in context
    return HookAuthDriver(acme_client, context.config.auth, context.common_name).authorize(csr, hooks)
