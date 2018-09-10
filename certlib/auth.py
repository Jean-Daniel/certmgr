import datetime
import os
import time
from typing import Dict, List, NamedTuple, Optional

import collections
from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certlib.config import HttpAuthDef
from .config import AuthType
from .context import CertificateContext
from .logging import log
from .utils import Hooks


def _get_challenge(authorization_resource: messages.AuthorizationResource, ty: str) -> Optional[messages.ChallengeBody]:
    for challenge in authorization_resource.body.challenges:
        if ty == challenge.typ:
            return challenge
    return None


def authorize_noop(acme_client, csr: x509.CertificateSigningRequest) -> messages.OrderResource:
    order = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))  # type: messages.OrderResource
    for authzr in order.authorizations:  # type: messages.AuthorizationResource
        status = authzr.body.status
        domain_name = authzr.body.identifier.value
        if status != messages.STATUS_VALID:
            log.raise_error('Domain "%s" not authorized and auth disabled (status: %s)', domain_name, status)
    return order


def authorize_http(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    auth: HttpAuthDef = context.config.auth
    order: messages.OrderResource = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))

    valid_authzr: List[messages.AuthorizationResource] = []
    pending_authzr: List[messages.AuthorizationResource] = []

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
    challenge_http_responses = {}
    for authzr in pending_authzr:
        domain_name = authzr.body.identifier.value
        http_challenge_directory = auth.challenge_directory(domain_name)
        if not http_challenge_directory:
            log.raise_error("[%s] no http challenge directory specified", domain_name)
        challenge = _get_challenge(authzr, 'http-01')
        if not challenge:
            log.raise_error('[%s] Unsupported http-01 challenge', domain_name)
        challenge_file_path = os.path.join(http_challenge_directory, challenge.chall.encode('token'))
        log.debug('Setting http acme-challenge for "%s" in file "%s"', domain_name, challenge_file_path)
        try:
            os.makedirs(os.path.dirname(challenge_file_path), 0o755, exist_ok=True)
            with open(challenge_file_path, 'w') as f:
                f.write(challenge.validation(acme_client.net.key))
                os.fchmod(f.fileno(), 0o644)

            challenge_http_responses[domain_name] = challenge_file_path
            hooks.add('set_http_challenge', domain=domain_name, file=challenge_file_path)
        except Exception as e:
            # remove already saved challenges
            for challenge_file in challenge_http_responses.values():
                # FIXME: ignore error ?
                os.remove(challenge_file)
            log.raise_error('[%s] Unable to create acme-challenge file "%s"', domain_name, challenge_file_path, cause=e)
    try:
        hooks.call()
        # Process authorizations
        valid_authzr += _get_authorizations(acme_client, pending_authzr, auth.retry, auth.delay)
    except Exception:
        for challenge_file in challenge_http_responses.values():
            # FIXME: ignore error ?
            os.remove(challenge_file)
        raise

    # Cleanup challenges
    for domain_name, challenge_file in challenge_http_responses.items():
        log.debug('Removing http acme-challenge for %s', domain_name)
        os.remove(challenge_file)
        hooks.add('clear_http_challenge', domain=domain_name, file=challenge_file)
    hooks.call()

    # Not required, but better be a good citizen
    order.update(authorizations=valid_authzr)

    return order


class AuthorizationTuple(NamedTuple):
    datetime: datetime.datetime
    authorization_resource: messages.AuthorizationResource


def _get_authorizations(acme_client: client.ClientV2, authzrs: List[messages.AuthorizationResource], retry: int, delay: int):
    # answer challenges
    for authzr in authzrs:
        domain_name = authzr.body.identifier.value
        with log.prefix("  [{}] ".format(domain_name)):
            challenge = _get_challenge(authzr, 'http-01')
            try:
                log.debug('Answering challenge')
                acme_client.answer_challenge(challenge, challenge.response(acme_client.net.key))
            except Exception as e:
                log.raise_error('Error answering challenge', cause=e)

    # poll for authorizations
    valid_authzr: List[messages.AuthorizationResource] = []
    retry_counters: Dict[str, int] = collections.defaultdict(int)
    pending_authzr = [AuthorizationTuple(datetime.datetime.now(), authzr) for authzr in authzrs]
    while pending_authzr:
        when, authzr = pending_authzr.pop(0)
        domain_name = authzr.body.identifier.value
        with log.prefix("  [{}] ".format(domain_name)):
            now = datetime.datetime.now()
            if now < when:
                seconds = (when - now).seconds
                if 0 < seconds:
                    time.sleep(seconds)
                    log.debug('Polling')
            try:
                authzr, response = acme_client.poll(authzr)
                if 200 != response.status_code:
                    log.warning('%s while waiting for domain challenge', response)
                    pending_authzr.append(AuthorizationTuple(acme_client.retry_after(response, default=delay), authzr))
                    continue
            except Exception as e:
                log.raise_error('Error polling for authorization', cause=e)
                assert False  # help type checker

            retry_counters[domain_name] += 1
            if messages.STATUS_VALID == authzr.body.status:
                valid_authzr.append(authzr)
                log.progress('Domain authorized (until %)', authzr.body.expires)
                continue
            elif messages.STATUS_INVALID == authzr.body.status:
                e = _get_challenge(authzr, 'http-01').error
                log.raise_error('Authorization failed : %s', e.detail if e else 'Unknown error')
            elif messages.STATUS_PENDING == authzr.body.status:
                if retry_counters[domain_name] > retry:
                    log.debug('Max retry reached')
                    log.raise_error('Authorization timed out')
                else:
                    log.debug('Retrying')
                    pending_authzr.append(AuthorizationTuple(acme_client.retry_after(response, default=delay), authzr))
            else:
                log.raise_error('Unexpected authorization status "%s"', authzr.body.status)
    return valid_authzr


def authorize_hook(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    # TODO: execute hook
    return authorize_noop(acme_client)


def authorize(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    auth = context.config.auth
    if auth.type == AuthType.noop:
        return authorize_noop(acme_client, csr)
    elif auth.type == AuthType.http:
        return authorize_http(csr, context, acme_client, hooks)
    elif auth.type == AuthType.hook:
        return authorize_hook(csr, context, hooks)
