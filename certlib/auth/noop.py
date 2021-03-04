from typing import List

from acme import client, messages
from cryptography import x509

from .driver import AuthDriver
from ..logging import log
from ..utils import Hooks


class NoopAuthDriver(AuthDriver):
    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks):
        log.raise_error('Some domains requires auth but auth is disabled')


def authorize_noop(csr: bytes, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return NoopAuthDriver(acme_client).authorize(csr, hooks)
