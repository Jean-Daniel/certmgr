import os
from typing import List

from acme import client, messages
from cryptography import x509

from .driver import AcmeAuthDriver
from ..config import HttpAuthDef
from ..logging import log
from ..utils import Hooks


# -------- HTTP Auth
class HttpAuthDriver(AcmeAuthDriver):
    challenge_type = 'http-01'

    def __init__(self, acme_client: client.ClientV2, auth: HttpAuthDef):
        super().__init__(acme_client)
        self.auth = auth
        self.challenge_http_responses = {}

    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks):
        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            http_challenge_directory = self.auth.challenge_directory(domain_name)
            if not http_challenge_directory:
                log.raise_error("[%s] no http challenge directory specified", domain_name)
            challenge = self.get_challenge(authzr)
            if not challenge:
                log.raise_error('[%s] Unsupported http-01 challenge', domain_name)
            challenge_file_path = os.path.join(http_challenge_directory, challenge.chall.encode('token'))
            log.debug('writing http acme-challenge for "%s" in file "%s"', domain_name, challenge_file_path)
            try:
                os.makedirs(os.path.dirname(challenge_file_path), 0o755, exist_ok=True)
                with open(challenge_file_path, 'w') as f:
                    f.write(challenge.validation(self.acme_client.net.key))
                    os.fchmod(f.fileno(), 0o644)

                self.challenge_http_responses[domain_name] = challenge_file_path
                hooks.add('set_http_challenge', domain=domain_name, file=challenge_file_path)
            except Exception as e:
                # remove already saved challenges
                self.abort()
                log.raise_error('[%s] Unable to create acme-challenge file "%s"', domain_name, challenge_file_path, cause=e)

        try:
            hooks.call()
            # Process authorizations
            valid_authzr = self.get_authorizations(authzrs, self.auth.retry, self.auth.delay)
        except Exception:
            self.abort()
            raise

        for domain_name, challenge_file in self.challenge_http_responses.items():
            log.debug('deleting http acme-challenge for %s', domain_name)
            os.remove(challenge_file)
            hooks.add('clear_http_challenge', domain=domain_name, file=challenge_file)
        hooks.call()

        return valid_authzr

    def abort(self):
        for challenge_file in self.challenge_http_responses.values():
            # FIXME: ignore error ?
            os.remove(challenge_file)


def authorize_http(csr: bytes, auth: HttpAuthDef, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return HttpAuthDriver(acme_client, auth).authorize(csr, hooks)
