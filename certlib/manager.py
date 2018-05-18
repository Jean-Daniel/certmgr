import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import time
from argparse import Namespace
from typing import Iterable, Optional

from acme import client, messages
from asn1crypto import ocsp as asn1_ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from . import AcmeError, actions, acme
from .acme import handle_authorizations
from .actions import Action, update_links
from .config import FileManager, Configuration
from .context import CertificateContext, CertificateItem
from .crypto import PrivateKey, load_full_chain, get_dhparam_size, get_ecparam_curve, generate_dhparam, generate_ecparam, Certificate
from .logging import log
from .ocsp import OCSP
from .sct import fetch_sct, SCTLog
from .utils import ArchiveOperation, Hooks, commit_file_transactions
from .verify import verify_certificate_installation


def _sct_datetime(sct_timestamp):
    return datetime.datetime.utcfromtimestamp(sct_timestamp / 1000)


class UpdateAction(Action):

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client: client.ClientV2):
        if not args.certs and not args.params and not args.ocsp and not args.sct:
            args.certs = True
            args.params = True
            args.ocsp = True
            args.sct = True
        super().__init__(config, fs, args, acme_client)
        self._done = []
        self._services = set()
        self._root_certificates = {}

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
        try:
            update_links(context)
        except AcmeError as e:
            log.error("symlinks update error: %s", str(e))

    def process_certificates(self, context: CertificateContext):
        log.info('Update Certificates')

        # For each types, check if the cert exists and is valid (params match and not about to expire)
        for item in context:  # type: CertificateItem
            with log.prefix('  - [{}] '.format(item.type.upper())):
                if self.args.force or item.should_renew(self.config.int('renewal_days')):
                    log.debug('Generating key')
                    key = PrivateKey.create(item.type, item.params)

                    log.debug('Requesting certificate for "%s" with alt names: "%s"', context.common_name, ', '.join(context.domain_names))
                    csr = key.create_csr(context.common_name, context.domain_names, context.config.ocsp_must_staple)
                    order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
                    if self.args.no_auth:
                        for authorization_resource in order.authorizations:  # type: messages.AuthorizationResource
                            status = authorization_resource.body.status
                            domain_name = authorization_resource.body.identifier.value
                            if messages.STATUS_VALID != status:
                                raise AcmeError('Domain "%s" not authorized and auth disabled (status: %s)', domain_name, status)
                    else:
                        handle_authorizations(order, self.fs, self.acme_client,
                                              self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'), Hooks(self.config.hooks))

                    try:
                        order = self.acme_client.finalize_order(order, datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('cert_poll_time')))
                        certificate, chain = load_full_chain(order.fullchain_pem.encode('ascii'))
                        if not certificate or not chain:
                            raise AcmeError("Certificate generation failed. Missing certificate or chain in response.")
                        item.update(key, certificate, chain)
                    except Exception as e:
                        raise AcmeError('[{}:{}] Certificate issuance failed', item.name, item.type.upper()) from e

                    log.info('New certificate issued')

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
                    log.info('Generating %s bit Diffie-Hellman parameters', dhparam_size)
                    dhparams = generate_dhparam(dhparam_size)
                if ecparam_curve and not ecparams:
                    log.info('Generating %s elliptical curve parameters', ecparam_curve)
                    ecparams = generate_ecparam(ecparam_curve)
                context.update(dhparams, ecparams)
            elif context.dhparams or context.ecparams:
                log.debug("Removing DH and EC params")
                context.update(None, None)

            if context.params_updated:
                log.debug("DH and EC params updated")
            else:
                log.debug("DH and EC up to date")

    def update_ocsp(self, context: CertificateContext):
        if not self.fs.directory('ocsp'):
            return

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
                tbs_request = asn1_ocsp.TBSRequest({
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
                ocsp_request = asn1_ocsp.OCSPRequest({
                    'tbs_request': tbs_request,
                    'optional_signature': None
                })

                for ocsp_url in ocsp_urls:
                    ocsp_response = OCSP.fetch(ocsp_url, ocsp_request, last_update)
                    if ocsp_response:
                        if 'successful' != ocsp_response.response_status:
                            log.warning('OCSP request received "%s" from %s', ocsp_response.response_status, ocsp_url)
                            continue

                        ocsp_status = ocsp_response.response_status
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

                        log.info('Updating OCSP response from %s', ocsp_url)
                        item.ocsp_response = ocsp_response
                        break

                    elif ocsp_response is False:
                        log.debug('OCSP response from %s has not been updated', ocsp_url)
                        break
                else:
                    log.warning('Unable to retrieve OCSP response')

    def update_signed_certificate_timestamps(self, context: CertificateContext):
        if not self.fs.directory('sct'):
            return

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
                            log.info('[%s] Saving SCT (%s)', ct_log.name, _sct_datetime(sct_data.timestamp).isoformat())
                            item.update_sct(ct_log, sct_data)
                        elif sct_data:
                            log.debug('[%s] SCT up to date (%s)', ct_log.name, _sct_datetime(sct_data.timestamp).isoformat())

    def apply_changes(self, context: CertificateContext):
        # commit transaction, execute hooks, schedule service reload, …
        transactions = []
        owner = self.config.fileowner()
        hooks = Hooks(self.config.hooks)

        if context.params_updated:
            trx = context.save_params(owner)
            if trx:
                transactions.append(trx)
                if trx.is_write:
                    hooks.add('params_installed', certificate_name=context.name, file=trx.file_path)
                # TODO: hooks('removed')

        # save private keys
        for item in context:  # type: CertificateItem
            if item.certificate_updated or context.params_updated:
                trx = item.save_certificate(owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('certificate_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

                root = self.root_certificate(item.type)
                if root:
                    trx = item.save_certificate(owner, root)
                    if trx:
                        transactions.append(trx)
                        if trx.is_write:
                            hooks.add('full_certificate_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)
                        # TODO: hooks('removed')
                else:
                    # archive existing file
                    path = item.filepath('full_certificate')
                    if path:
                        transactions.append(ArchiveOperation('certificates', path))

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
            commit_file_transactions(transactions, self.fs.archive_dir(context.name))
            self.update_services(context.config.services)
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

    def update_services(self, services: Iterable[str]):
        if services:
            self._services.update(services)

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


class AcmeManager(object):

    def __init__(self, script_dir, script_name):
        self.script_dir = script_dir
        self.script_name = script_name
        self.script_version = '1.0.0'

        argparser = argparse.ArgumentParser(description='ACME Certificate Manager')

        argparser.add_argument('--version', action='version', version='%(prog)s ' + self.script_version)

        argparser.add_argument('-c', '--config',
                               dest='config_path', default=self.script_name + '.json', metavar='CONFIG_PATH',
                               help='Specify file path for config')
        argparser.add_argument('-w', '--randomwait',
                               action='store_true', dest='random_wait', default=False,
                               help='Wait for a random time before executing')

        # Logging options
        argparser.add_argument('-q', '--quiet',  # error
                               action='store_true', dest='quiet', default=False,
                               help="Don't print status messages to stdout or warnings to stderr")
        argparser.add_argument('-v', '--verbose', '--info',
                               action='store_true', dest='verbose', default=False,
                               help='Print more detailed status messages to stdout')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='Print detailed debugging information to stdout')

        argparser.add_argument('--color',
                               action='store_true', dest='color', default=True,
                               help='Colorize output')
        argparser.add_argument('--no-color',
                               action='store_true', dest='no_color', default=False,
                               help='Suppress colorized output')

        subparsers = argparser.add_subparsers(description='acmetool subcommand', dest='action')

        action = subparsers.add_parser('check', help='check installed files permissions and symlinks')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.CheckAction)

        action = subparsers.add_parser('revoke', help='revoke certificates')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.RevokeAction)

        action = subparsers.add_parser('auth', help='perform domain authentification')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.AuthAction)

        action = subparsers.add_parser('verify', help='verify installed certificates')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.VerifyAction)

        action = subparsers.add_parser('update', help='update keys, certificates, oscp, sct and params')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=UpdateAction)
        action.add_argument('--certs',
                            action='store_true', dest='certs', default=False,
                            help='Update certificates only')
        action.add_argument('--params',
                            action='store_true', dest='params', default=False,
                            help='Update EC and DH parameters only')
        action.add_argument('--ocsp',
                            action='store_true', dest='ocsp', default=False,
                            help='Update OCSP responses only')
        action.add_argument('--sct',
                            action='store_true', dest='sct', default=False,
                            help='Update Signed Certificate Timestamps only')

        action.add_argument('--verify',
                            action='store_true', dest='verify', default=False,
                            help='Verify installed certificates')

        action.add_argument('--force',
                            action='store_true', dest='force', default=False,
                            help='Force refresh of existing files even if not needed')
        action.add_argument('--no-auth',
                            action='store_true', dest='no_auth', default=False,
                            help='Assume all domain names are already verified and do not perform any authorization')

        # argparser.set_default_subparser('update')
        # action.add_argument('--fast-dhparams',
        #                        action='store_true', dest='fast_dhparams', default=False,
        #                        help='Using 2ton.com.au online generator to get dhparams instead of generating them locally')

        self.args = argparser.parse_args()
        if not getattr(self.args, 'cls', None):
            self.args = argparser.parse_args(sys.argv[1:] + ['update'])

        level = logging.WARNING
        if self.args.quiet:
            level = logging.ERROR
        elif self.args.debug:
            level = logging.DEBUG
        elif self.args.verbose:
            level = logging.INFO

        # reset root logger
        log.reset(self.args.color and not self.args.no_color, level)

        self.config, self.fs = Configuration.load(self.args.config_path, ('.', os.path.join('/etc', self.script_name), self.script_dir))
        # update color setting
        log.color = self.config.bool('color_output')

    def connect_client(self) -> client.ClientV2:
        resource_dir = os.path.join(self.script_dir, self.fs.directory('resource'))
        archive_dir = self.fs.archive_dir('client')
        with log.prefix('[acme] '):
            return acme.connect_client(resource_dir, self.config.account['email'], self.config.get('acme_directory_url'),
                                       self.config.account.get('passphrase'), archive_dir)

    def _run(self):
        acme_client = None
        cls = self.args.cls
        if cls.has_acme_client:
            acme_client = self.connect_client()
        action = cls(self.config, self.fs, self.args, acme_client)
        for certificate_name in self.args.certificate_names or self.config.certificates.keys():
            cert = self.config.certificates.get(certificate_name)
            if not cert:
                log.warning("requested certificate '%s' does not exists in config", certificate_name)
                continue
            try:
                with log.prefix('[{}] '.format(cert.name)):
                    action.run(CertificateContext(cert, self.fs))
            except AcmeError as e:
                log.error("[%s] processing failed. No files updated\n%s", cert.name, str(e), print_exc=True)

        action.finalize()

    def run(self):
        log.info('\n----- %s executed at %s', self.script_name, str(datetime.datetime.now()))
        lock_path = self.fs.filepath('lock')
        if self.args.random_wait:
            delay_seconds = min(random.randrange(min(self.config.int('min_run_delay'), self.config.int('max_run_delay')),
                                                 max(self.config.int('min_run_delay'), self.config.int('max_run_delay'))), 86400)

            def _plural(duration, unit):
                if 0 < duration:
                    return '{duration} {unit}{plural} '.format(duration=duration, unit=unit, plural='' if (1 == duration) else 's')
                return ''

            log.debug('Waiting for %s%s%s',
                      _plural(int(delay_seconds / 3600), 'hour'), _plural(int((delay_seconds % 3600) / 60), 'minute'),
                      _plural((delay_seconds % 60), 'second'))
            time.sleep(delay_seconds)
        if lock_path:
            lock_file = open(lock_path, 'wb')

            if not try_lock(lock_file):
                if self.args.random_wait:
                    log.debug('Waiting for other running client instance')
                    while not try_lock(lock_file):
                        time.sleep(random.randrange(5, 30))
                else:
                    raise AcmeError('Client already running')

            with contextlib.closing(lock_file):
                self._run()
        else:
            # not lock path specified.
            self._run()


def try_lock(lock_file) -> bool:
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def debug_hook(ty, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(ty, value, tb)
    else:
        import traceback
        import pdb
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(ty, value, tb)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()
