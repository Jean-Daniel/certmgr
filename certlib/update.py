import argparse
import datetime
import hashlib
import json
import os
import subprocess
import time
from typing import List, Optional

from acme import client, messages
from asn1crypto import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from . import AcmeError
from .acme import handle_authorizations
from .actions import Action, prune_achives, update_links
from .config import Configuration
from .context import CertificateContext, CertificateItem
from .crypto import Certificate, PrivateKey, fetch_dhparam, generate_dhparam, generate_ecparam, get_dhparam_size, get_ecparam_curve, load_full_chain
from .logging import log
from .ocsp import OCSP
from .sct import SCTLog, fetch_sct
from .utils import ArchiveOperation, Hooks, commit_file_transactions
from .verify import verify_certificate_installation


def _sct_datetime(sct_timestamp):
    return datetime.datetime.utcfromtimestamp(sct_timestamp / 1000)


class UpdateAction(Action):

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser):
        super().add_arguments(parser)
        parser.add_argument('--certs',
                            action='store_true', dest='certs', default=False,
                            help='Update certificates only')
        parser.add_argument('--params',
                            action='store_true', dest='params', default=False,
                            help='Update EC and DH parameters only')
        parser.add_argument('--ocsp',
                            action='store_true', dest='ocsp', default=False,
                            help='Update OCSP responses only')
        parser.add_argument('--sct',
                            action='store_true', dest='sct', default=False,
                            help='Update Signed Certificate Timestamps only')

        parser.add_argument('--verify',
                            action='store_true', dest='verify', default=False,
                            help='Verify installed certificates')

        parser.add_argument('--force',
                            action='store_true', dest='force', default=False,
                            help='Force refresh of existing files even if not needed')
        parser.add_argument('--no-auth',
                            action='store_true', dest='no_auth', default=False,
                            help='Assume all domain names are already verified and do not perform any authorization')
        parser.add_argument('--fast-dhparams',
                            action='store_true', dest='fast_dhparams', default=False,
                            help='Using 2ton.com.au online generator to get dhparams instead of generating them locally')

    def __init__(self, config: Configuration, args: argparse.Namespace, contexts: List[CertificateContext], acme_client: client.ClientV2):
        if not args.certs and not args.params and not args.ocsp and not args.sct:
            args.certs = True
            args.params = True
            args.ocsp = True
            args.sct = True
        super().__init__(config, args, contexts, acme_client)
        self._done = []
        self._services = set()
        self._root_certificates = {}
        # counter used to avoid fetching duplicated dhparam when using dhparam server.
        # using counter in decreasing order so if a dhparam rollout occurs on the server
        # while updating the certificates, we don't accidentally fetch 2 times the same param
        self._counter = len(contexts)

    def root_certificate(self, key_type: str) -> Optional[Certificate]:
        if key_type not in self._root_certificates:
            cert_path = os.path.join(os.path.dirname(self.config.path), 'root_cert.{}.pem'.format(key_type))
            self._root_certificates[key_type] = Certificate.load(cert_path)
        return self._root_certificates[key_type]

    def run(self, context: CertificateContext):
        if self.args.certs:
            self.process_certificates(context)
        if self.args.params:
            self.process_params(context)
        if self.args.ocsp:
            self.update_ocsp(context)
        if self.args.sct:
            self.update_signed_certificate_timestamps(context)

        self.apply_changes(context)
        self._done.append(context)
        # Fixup links
        try:
            update_links(self.config.data_dir, context)
        except AcmeError as e:
            log.error("symlinks update error: %s", str(e))
        # Cleanup Archives
        prune_achives(os.path.join(self.config.data_dir, 'archives', context.name), self.config.int('archive_days'))

    def process_certificates(self, context: CertificateContext):
        log.info('Update Certificates')

        # For each types, check if the cert exists and is valid (params match and not about to expire)
        for item in context:  # type: CertificateItem
            with log.prefix('  - [{}] '.format(item.type.upper())):
                if self.args.force or item.should_renew(self.config.int('renewal_days')):
                    log.progress('Generating key')
                    key = PrivateKey.create(item.type, item.params)

                    log.debug('Requesting certificate for "%s" with alt names: "%s"', context.common_name, ', '.join(context.alt_names))
                    csr = key.create_csr(context.common_name, context.alt_names, context.config.ocsp_must_staple)
                    order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
                    if self.args.no_auth:
                        for authorization_resource in order.authorizations:  # type: messages.AuthorizationResource
                            status = authorization_resource.body.status
                            domain_name = authorization_resource.body.identifier.value
                            if messages.STATUS_VALID != status:
                                log.raise_error('Domain "%s" not authorized and auth disabled (status: %s)', domain_name, status)
                    else:
                        handle_authorizations(order, self.config.http_challenge_directory, self.acme_client,
                                              self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'), Hooks(self.config.hooks))

                    try:
                        order = self.acme_client.finalize_order(order, datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('cert_poll_time')))
                        certificate, chain = load_full_chain(order.fullchain_pem.encode('ascii'))
                        if not certificate or not chain:
                            log.raise_error("Certificate generation failed. Missing certificate or chain in response.")
                        item.update(key, certificate, chain)
                    except Exception as e:
                        log.raise_error('Certificate issuance failed', cause=e)

                    log.progress('New certificate issued')

    def process_params(self, context: CertificateContext):
        log.info('Update DH and EC params')

        with log.prefix("  - "):
            if not self.args.certs and not self.args.force:
                log.debug("Trying to update params without updating certificate. Will update them only if configuration did change")

            # Force refresh when certificates are updated
            force = self.args.force or context.updated

            # Updating dhparams
            dhparams = context.dhparams
            dhparam_size = context.config.dhparam_size
            if dhparams:
                if force or not dhparam_size:
                    dhparams = None
                elif dhparam_size and dhparam_size != get_dhparam_size(dhparams):
                    log.debug('Diffie-Hellman parameters are not %s bits', dhparam_size)
                    dhparams = None

            ecparams = context.ecparams
            ecparam_curve = context.config.ecparam_curve
            if ecparams:
                if force or not ecparam_curve:
                    ecparams = None
                elif ecparam_curve and ecparam_curve != get_ecparam_curve(ecparams):
                    log.debug('Elliptical curve parameters is not %s', ecparam_curve)
                    ecparams = None

            if dhparam_size or ecparam_curve:
                # generate params if needed
                if dhparam_size and not dhparams:
                    if self.args.fast_dhparams:
                        dhparams = fetch_dhparam(dhparam_size, self._counter)
                    else:
                        dhparams = generate_dhparam(dhparam_size)
                if ecparam_curve and not ecparams:
                    ecparams = generate_ecparam(ecparam_curve)
                context.update(dhparams, ecparams)
            elif context.dhparams or context.ecparams:
                log.debug("Removing DH and EC params")
                context.update(None, None)

            if context.params_updated:
                log.debug("DH and EC params updated")
            else:
                log.debug("DH and EC up to date")

            self._counter -= 1

    def update_ocsp(self, context: CertificateContext):
        log.info('Update OCSP Response')
        for item in context:  # type: CertificateItem
            # ignore ocsp if explicitly disabled for this certificate
            if not context.config.ocsp_responder_urls:
                item.ocsp_response = None
                continue

            with log.prefix('  - [{}] '.format(item.type.upper())):
                if not item.certificate:
                    log.warning("certificate not found. Can't update OCSP response")
                    continue

                ocsp_response = item.ocsp_response
                if (ocsp_response and ('good' == ocsp_response.response_status.lower())
                        and (ocsp_response.serial_number == item.certificate.serial_number)):
                    last_update = ocsp_response.this_update
                    log.debug('Have stapled OCSP response updated at %s', last_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                else:
                    last_update = None

                ocsp_urls = (item.certificate.ocsp_urls or context.config.ocsp_responder_urls)
                if not ocsp_urls:
                    log.warning('No OCSP responder URL and no default set')
                    continue

                chain = item.chain
                issuer_certificate = chain[0] if chain else self.root_certificate(item.type)
                issuer_name = issuer_certificate.x509_certificate.subject.public_bytes(default_backend())
                issuer_key = issuer_certificate.x509_certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
                tbs_request = ocsp.TBSRequest({
                    'request_list': [
                        {
                            'req_cert': {
                                'hash_algorithm': {'algorithm': 'sha1'},
                                'issuer_name_hash': hashlib.sha1(issuer_name).digest(),
                                'issuer_key_hash': hashlib.sha1(issuer_key).digest(),
                                'serial_number': item.certificate.serial_number,
                            },
                            'single_request_extensions': None
                        }
                    ],
                    'request_extensions': None  # [{'extn_id': 'nonce', 'critical': False, 'extn_value': os.urandom(16)}]
                    # we don't appear to be getting the nonce back, so don't send it
                })
                ocsp_request = ocsp.OCSPRequest({
                    'tbs_request': tbs_request,
                    'optional_signature': None
                })

                for ocsp_url in ocsp_urls:
                    ocsp_response = OCSP.fetch(ocsp_url, ocsp_request, last_update)
                    if ocsp_response:
                        if 'successful' != ocsp_response.response_status:
                            log.warning('OCSP request received "%s" from %s', ocsp_response.response_status, ocsp_url)
                            continue

                        ocsp_status = ocsp_response.cert_status
                        this_update = ocsp_response.this_update
                        log.debug('Retrieved OCSP status "%s" from %s updated at %s', ocsp_status.upper(),
                                  ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                        if 'good' != ocsp_status.lower():
                            log.warning('certificate has OCSP status "%s" from %s updated at %s', ocsp_status.upper(),
                                        ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                            continue

                        if this_update == last_update:
                            log.debug('OCSP response from %s has not been updated', ocsp_url)
                            break

                        log.progress('Updating OCSP response from %s', ocsp_url)
                        item.ocsp_response = ocsp_response
                        break

                    elif ocsp_response is False:
                        log.debug('OCSP response from %s has not been updated', ocsp_url)
                        break
                else:
                    log.warning('Unable to retrieve OCSP response')

    def update_signed_certificate_timestamps(self, context: CertificateContext):
        if not context.config.ct_submit_logs:
            return

        log.info('Update Signed Certificate Timestamps')

        for item in context:  # type: CertificateItem
            with log.prefix('  - [{}] '.format(item.type.upper())):
                if not item.certificate:
                    log.warning('certificate not found')
                    continue

                for ct_log in context.config.ct_submit_logs:  # type: SCTLog
                    sct_data = fetch_sct(ct_log, item.certificate, item.chain)
                    if sct_data:
                        existing_sct_data, _ = item.sct(ct_log)
                        if sct_data and sct_data != existing_sct_data:
                            log.progress('[%s] Saving SCT (%s)', ct_log.name, _sct_datetime(sct_data.timestamp).isoformat())
                            item.update_sct(ct_log, sct_data)
                        elif sct_data:
                            log.debug('[%s] SCT up to date (%s)', ct_log.name, _sct_datetime(sct_data.timestamp).isoformat())

    def apply_changes(self, context: CertificateContext):
        # commit transaction, execute hooks, schedule service reload, …
        transactions = []
        hooks = Hooks(self.config.hooks)
        owner = context.config.fileowner

        if context.params_updated:
            trx = context.save_params(owner)
            if trx:
                transactions.append(trx)
                if trx.is_write:
                    hooks.add('params_installed', certificate_name=context.name, file=trx.file_path)
                # TODO: hooks('removed')

        # save private keys
        for item in context:  # type: CertificateItem
            root = self.root_certificate(item.type)
            if not root:
                # archive existing file
                path = item.certificate_path(full=True)
                if path:
                    transactions.append(ArchiveOperation('certificates', path))
                    # TODO: hooks('removed')

            if item.certificate_updated or context.params_updated:
                trx = item.save_certificate(owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('certificate_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

                if root:
                    trx = item.save_certificate(owner, root)
                    if trx:
                        transactions.append(trx)
                        hooks.add('full_certificate_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

                # Full Key
                trx = item.save_key(owner, with_certificate=True)
                if trx:
                    transactions.append(trx)
                    if trx.is_write:
                        hooks.add('full_key_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)
                    # TODO: hooks('removed')

            if item.certificate_updated:
                trx = item.save_chain(owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('chain_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

                trx = item.save_key(owner)
                if trx:
                    transactions.append(trx)
                    # TODO: pass password to the hook ?
                    hooks.add('private_key_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)
            else:
                if (not item.key.encrypted and item.config.private_key.passphrase) or (item.key.encrypted and not item.config.private_key.passphrase):
                    log.info("Private key encryption configuration changed. Rewriting keys.")
                    # Replace existing file
                    op = item.save_key(owner, archive=False)
                    if op:
                        transactions.append(op)
                        hooks.add('private_key_installed', certificate_name=item.name, key_type=item.type, file=op.file_path)
                    op = item.save_key(owner, archive=False, with_certificate=True)
                    if op:
                        transactions.append(op)
                        hooks.add('full_key_installed', certificate_name=item.name, key_type=item.type, file=op.file_path)

            if item.ocsp_updated:
                trx = item.save_ocsp(owner)
                if trx:
                    transactions.append(trx)
                    if trx.is_write:
                        hooks.add('ocsp_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)
                    # TODO: hooks('removed')

            for ct_log in item.config.ct_submit_logs:
                sct_data, updated = item.sct(ct_log)
                if not updated:
                    continue
                trx = item.save_sct(ct_log, owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('sct_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path, ct_log_name=ct_log.name)
        if transactions:
            commit_file_transactions(transactions, self.config.archive_dir(context.name))
            services = context.config.services
            if services:
                self._services.update(services)
            hooks.call()

    def finalize(self):
        # Call hook usefull to sync status with other hosts
        updated = [context.name for context in self._done if context.updated]
        if updated:
            hooks = Hooks(self.config.hooks)
            hooks.add('certificates_updated', certificates=json.dumps(sorted(updated)))
            hooks.call()

        if self._reload_services() and self.args.verify:
            log.info("Waiting service reload before verifying")
            time.sleep(5)  # allow time for services to reload before verification

        # prune archives
        prune_achives(os.path.join(self.config.data_dir, 'archives', 'account'), self.config.int('archive_days'))

        # Verify is needed
        if self.args.verify:
            max_ocsp_verify_attempts = self.config.int('max_ocsp_verify_attempts')
            ocsp_verify_retry_delay = self.config.int('ocsp_verify_retry_delay')
            for context in self._done:
                with log.prefix("[{}] ".format(context.name)):
                    log.info("Verify certificates")
                    try:
                        verify_certificate_installation(context, max_ocsp_verify_attempts, ocsp_verify_retry_delay)
                    except AcmeError as e:
                        log.error("validation error: %s", str(e))

    def _reload_services(self) -> bool:
        reloaded = False
        for service_name in self._services:
            with log.prefix(" - [{}] ".format(service_name)):
                service_command = self.config.service(service_name)
                if service_command:
                    log.info('reloading service')
                    try:
                        output = subprocess.check_output(service_command, shell=True, stderr=subprocess.STDOUT)
                        reloaded = True
                        if output:
                            log.info('reload OK with result:\n%s', output)
                        else:
                            log.debug('reload OK')
                    except subprocess.CalledProcessError as e:
                        log.warning('reload failed, code: %s:\n%s', e.returncode, e.output)
                else:
                    log.error('no reload command registred')
        return reloaded
