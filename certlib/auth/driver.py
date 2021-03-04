import collections
import datetime
import time
from typing import Dict, List, NamedTuple, Optional, Type

from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..logging import log
from ..utils import Hooks


class AuthDriver:

    def __init__(self, acme_client: client.ClientV2):
        self.acme_client = acme_client

    def authorize(self, csr: bytes, hooks: Hooks) -> messages.OrderResource:
        valid_authzr: List[messages.AuthorizationResource] = []
        pending_authzr: List[messages.AuthorizationResource] = []

        order: messages.OrderResource = self.acme_client.new_order(csr)
        # collect pending auth resources
        for authzr in order.authorizations:  # type: messages.AuthorizationResource
            domain_name = authzr.body.identifier.value
            if messages.STATUS_VALID == authzr.body.status:
                log.debug('Domain "%s" already authorized (until %s)', domain_name, authzr.body.expires)
                valid_authzr.append(authzr)
            elif messages.STATUS_PENDING == authzr.body.status:
                log.progress('Requesting authorization for domain "%s"', domain_name)
                pending_authzr.append(authzr)
            else:
                log.raise_error('Unexpected status "%s" for authorization of %s', authzr.body.status, domain_name)

        # All auth where already valid, nothing to do
        if not pending_authzr:
            return order

        # Setup challenge responses
        valid_authzr += self.do_authorize(pending_authzr, hooks)

        # Not required, but better be a good citizen
        order.update(authorizations=valid_authzr)

        return order

    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks) -> List[messages.AuthorizationResource]:
        raise NotImplementedError()


class AuthorizationTuple(NamedTuple):
    datetime: datetime.datetime
    authorization_resource: messages.AuthorizationResource


class AcmeAuthDriver(AuthDriver):
    challenge_type: str

    def get_challenge(self, authorization_resource: messages.AuthorizationResource) -> Optional[Type[messages.ChallengeBody]]:
        for challenge in authorization_resource.body.challenges:
            if self.challenge_type == challenge.typ:
                return challenge
        return None

    def get_authorizations(self, authzrs: List[messages.AuthorizationResource], retry: int, delay: int):
        # answer challenges
        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            with log.prefix(f"  [{domain_name}] "):
                challenge = self.get_challenge(authzr)
                try:
                    log.debug('Answering challenge')
                    self.acme_client.answer_challenge(challenge, challenge.response(self.acme_client.net.key))
                except Exception as e:
                    log.raise_error('Error answering challenge', cause=e)

        # poll for authorizations
        valid_authzr: List[messages.AuthorizationResource] = []
        retry_counters: Dict[str, int] = collections.defaultdict(int)
        pending_authzr = [AuthorizationTuple(datetime.datetime.now(), authzr) for authzr in authzrs]
        while pending_authzr:
            when, authzr = pending_authzr.pop(0)
            domain_name = authzr.body.identifier.value
            with log.prefix(f"  [{domain_name}] "):
                now = datetime.datetime.now()
                if now < when:
                    seconds = (when - now).seconds
                    if 0 < seconds:
                        time.sleep(seconds)
                        log.debug('Polling')
                try:
                    authzr, response = self.acme_client.poll(authzr)
                    if 200 != response.status_code:
                        log.warning('%s while waiting for domain challenge', response)
                        pending_authzr.append(AuthorizationTuple(self.acme_client.retry_after(response, default=delay), authzr))
                        continue
                except Exception as e:
                    log.raise_error('Error polling for authorization', cause=e)
                    assert False  # help type checker

                retry_counters[domain_name] += 1
                if messages.STATUS_VALID == authzr.body.status:
                    valid_authzr.append(authzr)
                    log.progress('Domain authorized (until %s)', authzr.body.expires)
                    continue
                elif messages.STATUS_INVALID == authzr.body.status:
                    e = self.get_challenge(authzr).error
                    log.raise_error('Authorization failed : %s', e.detail if e else 'Unknown error')
                elif messages.STATUS_PENDING == authzr.body.status:
                    if retry_counters[domain_name] > retry:
                        log.debug('Max retry reached')
                        log.raise_error('Authorization timed out')
                    else:
                        log.debug('Retrying')
                        pending_authzr.append(AuthorizationTuple(self.acme_client.retry_after(response, default=delay), authzr))
                else:
                    log.raise_error('Unexpected authorization status "%s"', authzr.body.status)
        return valid_authzr
