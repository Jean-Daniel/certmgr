from typing import List, Optional

import dns
import dns.query
import dns.tsigkeyring
import dns.update
from acme import client, messages
from acme.challenges import DNS01
from cryptography import x509

from .driver import AcmeAuthDriver
from ..config import DnsAuthDef, TsigKey
from ..context import CertificateContext
from ..logging import log
from ..utils import Hooks


# -------- DNS Auth

class DnsAuthDriver(AcmeAuthDriver):
    challenge_type = 'dns-01'

    def __init__(self, acme_client: client.ClientV2, auth: DnsAuthDef):
        super().__init__(acme_client)
        self.auth = auth
        self.records = []

    def do_authorize(self, authzrs: List[messages.AuthorizationResource], hooks: Hooks):
        for authzr in authzrs:
            domain_name = authzr.body.identifier.value
            challenge: Optional[DNS01] = self.get_challenge(authzr)
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
            log.debug('add dns record "%s" to %s using key %s', record_name, server, key_spec.id)

            # relativize domain_name by stripping zone name
            n = dns.name.from_text(record_name)
            o = dns.name.from_text(zone)
            rel = n.relativize(o)

            keyring = dns.tsigkeyring.from_text({key_spec.id: key_spec.secret})
            update = dns.update.Update(zone, keyring=keyring, keyalgorithm=key_spec.algorithm)
            update.add(rel, 300, dns.rdatatype.TXT, challenge.validation(self.acme_client.net.key))
            try:
                response = dns.query.tcp(update, server[0], port=server[1])
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
                log.raise_error('[%s] add record return rcode %s', domain_name, dns.rcode.to_text(rcode))

        try:
            # Process authorizations
            valid_authzr = self.get_authorizations(authzrs, self.auth.retry, self.auth.delay)
        except Exception:
            self.cleanup()
            raise

        self.cleanup()

        return valid_authzr

    def cleanup(self):
        for key_spec, zone, server, name in self.records:
            keyring = dns.tsigkeyring.from_text({key_spec.id: key_spec.secret})
            update = dns.update.Update(zone, keyring=keyring, keyalgorithm=key_spec.algorithm)
            update.delete(name)
            try:
                log.debug('remove dns record "%s" from %s using key %s', name, server, key_spec.id)
                response = dns.query.tcp(update, server[0], port=server[1])
                if response.rcode() != dns.rcode.NOERROR:
                    log.warning('[%s.%s] DNS record cleanup failed: %s', name, zone, dns.rcode.to_text(response.rcode()))
            except Exception as ex:
                log.warning('[%s.%s] DNS record cleanup failed: %s', name, zone, str(ex))


def authorize_dns(csr: bytes, auth: DnsAuthDef, acme_client: client.ClientV2, hooks: Hooks) -> messages.OrderResource:
    return DnsAuthDriver(acme_client, auth).authorize(csr, hooks)
