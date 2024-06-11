from typing import List

from acme import client, messages

from .driver import AuthDriver
from ..config import HookAuthDef
from ..logging import log
from ..utils import Hooks


class HookAuthDriver(AuthDriver):

    def __init__(self, acme_client: client.ClientV2, auth: HookAuthDef, csr: bytes):
        super().__init__(acme_client)
        self.auth = auth
        self.csr = csr

    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks):
        if self.auth.each_domain:
            for authzr in authzrs:
                domain_name = authzr.body.identifier.value
                # TODO: tweak argument list
                if not self.auth.cmd.execute(common_name=domain_name):
                    log.raise_error('authentification hook failed for domain %s', domain_name)
        else:
            if not self.auth.cmd.execute(csr=self.csr.decode()):
                log.raise_error('authentification hook failed for domains %s', [authzr.body.identifier.value for authzr in authzrs])
        return authzrs  # FIXME: should update authzrs


def authorize_hook(csr: bytes, auth: HookAuthDef, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return HookAuthDriver(acme_client, auth, csr).authorize(csr, hooks)
