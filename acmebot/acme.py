import datetime
import os
import time
from typing import List, Dict, Optional

import collections
from acme import messages, client

from . import AcmeError, log
from .config import FileManager
from .utils import open_file


def get_challenge(authorization_resource: messages.AuthorizationResource, ty: str) -> Optional[messages.ChallengeBody]:
    for challenge in authorization_resource.body.challenges:
        if ty == challenge.typ:
            return challenge
    return None


AuthorizationTuple = collections.namedtuple('AuthorizationTuple', ['datetime', 'domain_name', 'authorization_resource'])


def handle_authorizations(order: messages.OrderResource, fs: FileManager, acme_client: client.ClientV2,
                          retry: int, delay: int) -> List[messages.AuthorizationResource]:
    authorizations = []
    authorization_resources = {}

    # collect pending auth resources
    for authorization_resource in order.authorizations:  # type: messages.AuthorizationResource
        domain_name = authorization_resource.body.identifier.value
        if messages.STATUS_VALID == authorization_resource.body.status:
            log.debug('%s already authorized', domain_name)
            authorizations.append(authorization_resource)
        elif messages.STATUS_PENDING == authorization_resource.body.status:
            log.info('Requesting authorization for %s', domain_name)
            authorization_resources[domain_name] = authorization_resource
        else:
            raise AcmeError('Unexpected status "{}" for authorization of {}', authorization_resource.body.status, domain_name)

    # All auth where already valid, nothing to do
    if not authorization_resources:
        return authorizations

    # Setup challenge responses
    challenge_http_responses = {}
    for domain_name, authorization_resource in authorization_resources.items():
        identifier = authorization_resource.body.identifier.value
        http_challenge_directory = fs.http_challenge_directory(identifier)
        if not http_challenge_directory:
            raise AcmeError("no http_challenge_directory directory specified for domain {}", domain_name)
        challenge = get_challenge(authorization_resource, 'http-01')
        if not challenge:
            raise AcmeError('Unable to use http-01 challenge for {}', domain_name)
        challenge_file_path = os.path.join(http_challenge_directory, challenge.chall.encode('token'))
        log.debug('Setting http acme-challenge for "%s" in file "%s"', domain_name, challenge_file_path)
        try:
            with open_file(challenge_file_path, 'w', 0o644) as f:
                f.write(challenge.validation(acme_client.net.key))
            challenge_http_responses[domain_name] = challenge_file_path
        except Exception as error:
            # remove already saved challenges
            for challenge_file in challenge_http_responses.values():
                os.remove(challenge_file)
            raise AcmeError('Unable to create acme-challenge file "{}"', challenge_file_path) from error
    try:
        # Process authorizations
        authorizations += _get_authorizations(acme_client, authorization_resources, retry, delay)
    except Exception:
        for challenge_file in challenge_http_responses.values():
            os.remove(challenge_file)
        raise

    # Cleanup challenges
    for domain_name, challenge_file in challenge_http_responses.items():
        log.debug('Removing http acme-challenge for %s', domain_name)
        os.remove(challenge_file)

    return authorizations


def _get_authorizations(acme_client: client.ClientV2, authorization_resources: Dict[str, messages.AuthorizationResource],
                        retry: int, delay: int) -> List[messages.AuthorizationResource]:
    # answer challenges
    for domain_name, authorization_resource in authorization_resources.items():
        log.debug('Answering challenge for %s', domain_name)
        challenge = get_challenge(authorization_resource, 'http-01')
        try:
            acme_client.answer_challenge(challenge, challenge.response(acme_client.net.key))
        except Exception as error:
            raise AcmeError('Error answering challenge for {}', domain_name) from error

    # poll for authorizations
    authorizations = []
    waiting = [AuthorizationTuple(datetime.datetime.now(), domain_name, authorization_resource)
               for domain_name, authorization_resource in authorization_resources.items()]
    attempts = collections.defaultdict(int)
    while waiting:
        when, domain_name, authorization_resource = waiting.pop(0)
        now = datetime.datetime.now()
        if now < when:
            seconds = (when - now).seconds
            if 0 < seconds:
                time.sleep(seconds)
                log.debug('Polling for %s', domain_name)
        try:
            authorization_resource, response = acme_client.poll(authorization_resource)
            if 200 != response.status_code:
                log.warning('%s while waiting for domain challenge for %s', response, domain_name)
                waiting.append(AuthorizationTuple(acme_client.retry_after(response, default=delay), domain_name, authorization_resource))
                continue
        except Exception as error:
            raise AcmeError('Error polling for authorization for {}', domain_name) from error

        attempts[authorization_resource] += 1
        if messages.STATUS_VALID == authorization_resource.body.status:
            authorizations.append(authorization_resource)
            log.debug('Authorization received')
            continue
        elif messages.STATUS_INVALID == authorization_resource.body.status:
            error = get_challenge(authorization_resource, 'http-01').error
            raise AcmeError('Authorization failed for domain {}: {}', domain_name, error.detail if error else 'Unknown error')
        elif messages.STATUS_PENDING == authorization_resource.body.status:
            if attempts[authorization_resource] > retry:
                log.debug('Max retry reached for domain %s', domain_name)
                raise AcmeError('Authorization timed out for {}', domain_name)
            else:
                log.debug('Retrying')
                waiting.append(AuthorizationTuple(acme_client.retry_after(response, default=delay), domain_name, authorization_resource))
        else:
            raise AcmeError('Unexpected authorization status "{}"', authorization_resource.body.status)

    return authorizations
