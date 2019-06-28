import collections
import datetime
import os
import time
from typing import Dict, List, NamedTuple, Optional, Type

from acme import challenges, client, messages
from acme.challenges import DNS01
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certlib.config import DnsAuthDef, HookAuthDef, HttpAuthDef, TsigKey
from .config import AuthType
from .context import CertificateContext
from .logging import log
from .utils import Hooks


class AuthDriver:
    def authorize(self, authzrs: List[messages.AuthorizationResource], acme_client: client.ClientV2, hooks: Hooks) -> List[messages.AuthorizationResource]:
        raise NotImplementedError()


def _authorize(driver: AuthDriver, csr: x509.CertificateSigningRequest, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    valid_authzr: List[messages.AuthorizationResource] = []
    pending_authzr: List[messages.AuthorizationResource] = []

    order: messages.OrderResource = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
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
    valid_authzr += driver.authorize(pending_authzr, acme_client, hooks)

    # Not required, but better be a good citizen
    order.update(authorizations=valid_authzr)

    return order


class AuthorizationTuple(NamedTuple):
    datetime: datetime.datetime
    authorization_resource: messages.AuthorizationResource


def _get_challenge(authorization_resource: messages.AuthorizationResource, ty: str) -> Optional[Type[challenges.KeyAuthorizationChallenge]]:
    for challenge in authorization_resource.body.challenges:
        if ty == challenge.typ:
            return challenge.chall
    return None


def _get_authorizations(acme_client: client.ClientV2, authzrs: List[messages.AuthorizationResource], retry: int, delay: int, challenge_type: str):
    # answer challenges
    for authzr in authzrs:
        domain_name = authzr.body.identifier.value
        with log.prefix("  [{}] ".format(domain_name)):
            challenge = _get_challenge(authzr, challenge_type)
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
                log.progress('Domain authorized (until %s)', authzr.body.expires)
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


# -------- Noop Auth

class NoopAuthDriver(AuthDriver):
    def authorize(self, authzrs: List[messages.AuthorizationResource], acme_client: client.ClientV2, hooks: Hooks):
        log.raise_error('Soem domains requires auth but auth is disabled')


def authorize_noop(csr: x509.CertificateSigningRequest, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return _authorize(NoopAuthDriver(), csr, acme_client, hooks)


# -------- HTTP Auth
class HttpAuthDriver(AuthDriver):
    def __init__(self, auth: HttpAuthDef):
        self.auth = auth
        self.challenge_http_responses = {}

    def authorize(self, authzrs: List[messages.AuthorizationResource], acme_client: client.ClientV2, hooks: Hooks):
        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            http_challenge_directory = self.auth.challenge_directory(domain_name)
            if not http_challenge_directory:
                log.raise_error("[%s] no http challenge directory specified", domain_name)
            challenge = _get_challenge(authzr, 'http-01')
            if not challenge:
                log.raise_error('[%s] Unsupported http-01 challenge', domain_name)
            challenge_file_path = os.path.join(http_challenge_directory, challenge.encode('token'))
            log.debug('Setting http acme-challenge for "%s" in file "%s"', domain_name, challenge_file_path)
            try:
                os.makedirs(os.path.dirname(challenge_file_path), 0o755, exist_ok=True)
                with open(challenge_file_path, 'w') as f:
                    f.write(challenge.validation(acme_client.net.key))
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
            valid_authzr = _get_authorizations(acme_client, authzrs, self.auth.retry, self.auth.delay, 'http-01')
        except Exception:
            self.abort()
            raise

        for domain_name, challenge_file in self.challenge_http_responses.items():
            log.debug('Removing http acme-challenge for %s', domain_name)
            os.remove(challenge_file)
            hooks.add('clear_http_challenge', domain=domain_name, file=challenge_file)
        hooks.call()

        return valid_authzr

    def abort(self):
        for challenge_file in self.challenge_http_responses.values():
            # FIXME: ignore error ?
            os.remove(challenge_file)


def authorize_http(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    driver = HttpAuthDriver(context.config.auth)
    return _authorize(driver, csr, acme_client, hooks)


# -------- DNS Auth

class DnsAuthDriver(AuthDriver):

    def __init__(self, auth: DnsAuthDef):
        self.auth = auth
        self.records = []

    def authorize(self, authzrs: List[messages.AuthorizationResource], acme_client: client.ClientV2, hooks: Hooks):
        import dns.name
        import dns.query
        import dns.update
        import dns.tsigkeyring

        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            challenge: Optional[DNS01] = _get_challenge(authzr, 'dns-01')
            if not challenge:
                log.raise_error('[%s] Unsupported dns-01 challenge', domain_name)

            zone = self.auth.zone(domain_name)
            if not zone:
                log.raise_error("[%s] DNS zone not specified", domain_name)

            server = self.auth.server(domain_name)
            if not server:
                log.raise_error("[%s] DNS server not specified", domain_name)

            key_spec: TsigKey = self.auth.key(domain_name)
            if not key_spec:
                log.raise_error("[%s] no TSIG key specified", domain_name)

            record_name = challenge.validation_domain_name(domain_name)
            log.debug('Setting dns record "%s"', record_name)

            # relativize domain_name by stripping zone name
            n = dns.name.from_text(record_name)
            o = dns.name.from_text(zone)
            rel = n.relativize(o)

            keyring = dns.tsigkeyring.from_text({key_spec.name: key_spec.secret})
            update = dns.update.Update(zone, keyring=keyring, keyalgorithm=key_spec.algorithm)
            update.add(rel, 300, dns.rdatatype.TXT, challenge.validation(acme_client.net.key))
            try:
                response = dns.query.tcp(update, server)
            except Exception as ex:
                self.cleanup()
                log.raise_error('Cannot add DNS record', cause=ex)
                raise  # silence flow analyzer warning

            rcode = response.rcode()
            if rcode == dns.rcode.NOERROR:
                log.debug('[%s] successfully added TXT record', domain_name)
                self.records.append((key_spec, zone, server, rel))  # tuple: key_spec, server, name
            else:
                self.cleanup()
                log.raise_error('add record return returns rcode %s', dns.rcode.to_text(rcode))

        try:
            # Process authorizations
            valid_authzr = _get_authorizations(acme_client, authzrs, self.auth.retry, self.auth.delay, 'dns-01')
        except Exception:
            self.cleanup()
            raise

        self.cleanup()

        return valid_authzr

    def cleanup(self):
        import dns

        for key_spec, zone, server, name in self.records:
            keyring = dns.tsigkeyring.from_text({key_spec.name: key_spec.secret})
            update = dns.update.Update(zone, keyring=keyring, keyalgorithm=key_spec.algorithm)
            update.delete(name)
            try:
                response = dns.query.tcp(update, server)
                if response.rcode() != dns.rcode.NOERROR:
                    log.warning('[%s.%s] DNS record cleanup failed: %s', name, zone, dns.rcode.to_text(response.rcode()))
            except Exception as ex:
                log.warning('[%s.%s] DNS record cleanup failed: %s', name, zone, str(ex))


def authorize_dns(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    driver = DnsAuthDriver(context.config.auth)
    return _authorize(driver, csr, acme_client, hooks)


# -------- Hook Auth

class HookAuthDriver(AuthDriver):

    def __init__(self, auth: HookAuthDef):
        self.auth = auth

    def authorize(self, authzrs: List[messages.AuthorizationResource], acme_client: client.ClientV2, hooks: Hooks):
        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            # TODO: tweak argument list
            self.auth.cmd.execute(common_name=domain_name)
        return authzrs  # FIXME: should update authzrs


def authorize_hook(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return _authorize(HookAuthDriver(context.config.auth), csr, acme_client, hooks)


def authorize(csr: x509.CertificateSigningRequest, context: CertificateContext, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    auth = context.config.auth
    if auth.type == AuthType.noop:
        return authorize_noop(csr, acme_client, hooks)
    elif auth.type == AuthType.http:
        return authorize_http(csr, context, acme_client, hooks)
    elif auth.type == AuthType.dns:
        return authorize_dns(csr, context, acme_client, hooks)
    elif auth.type == AuthType.hook:
        return authorize_hook(csr, context, acme_client, hooks)
