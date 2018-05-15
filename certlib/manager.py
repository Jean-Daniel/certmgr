import argparse
import datetime
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import time
import traceback
from argparse import Namespace
from logging import StreamHandler
from typing import Iterable, Optional

from acme import client, messages
from asn1crypto import ocsp as asn1_ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from . import log, AcmeError, actions, acme
from .acme import handle_authorizations
from .actions import Action
from .config import FileManager, Configuration, CertificateSpec, SCTLog
from .context import CertificateContext, CertificateItem
from .crypto import PrivateKey, load_full_chain, get_dhparam_size, get_ecparam_curve, generate_dhparam, generate_ecparam, Certificate
from .ocsp import ocsp_response_status, ocsp_response_serial_number, ocsp_response_this_update, fetch_ocsp_response
from .utils import Hooks, open_file, ColorFormatter, process_running, fetch_sct, commit_file_transactions
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

    def run(self, certificate: CertificateSpec):
        context = CertificateContext(certificate, self.fs)
        log.info('[%s] Update', context.name)
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

    def process_certificates(self, context: CertificateContext):
        log.info(' * Certificate')

        # For each types, check if the cert exists and is valid (params match and not about to expire)
        for item in context:  # type: CertificateItem
            if self.args.force or item.should_renew(self.config.int('renewal_days')):
                log.debug('   [%s:%s] Generating key', item.name, item.type.upper())
                key = PrivateKey.create(item.type, item.params)

                log.debug('   [%s:%s] Requesting certificate for "%s" with alt names: "%s"', item.name, item.type.upper(),
                          item.spec.common_name, ', '.join(item.spec.alt_names))
                csr = key.create_csr(item.spec.common_name, item.spec.alt_names, item.spec.ocsp_must_staple)
                order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
                if self.args.no_auth:
                    for authorization_resource in order.authorizations:  # type: messages.AuthorizationResource
                        status = authorization_resource.body.status
                        domain_name = authorization_resource.body.identifier.value
                        if messages.STATUS_VALID != status:
                            raise AcmeError('[%s:%s] Domain "%s" not authorized and auth disabled (status: %s)',
                                            item.name, item.type.upper(), domain_name, status)
                else:
                    handle_authorizations(order, self.fs, self.acme_client,
                                          self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'))

                try:
                    order = self.acme_client.finalize_order(order, datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('cert_poll_time')))
                    certificate, chain = load_full_chain(order.fullchain_pem.encode('ascii'))
                    item.update(key, certificate, chain)
                except Exception as e:
                    raise AcmeError('[{}:{}] Certificate issuance failed', item.name, item.type.upper()) from e

                log.info('   [%s:%s] New certificate issued', item.name, item.type.upper())

    def process_params(self, context: CertificateContext):
        log.info(' * DH and EC params')

        if not self.args.certs and not self.args.force:
            log.debug("   - Trying to update params without updating certificate. Will update them only if configuration did change")

        # Force refresh when certificates are updated
        force = self.args.force or context.updated

        # Updating dhparams
        dhparams = context.dhparams
        dhparam_size = context.spec.dhparam_size
        if dhparams:
            if force or not dhparam_size:
                dhparams = None
            elif dhparam_size and dhparam_size != get_dhparam_size(dhparams):
                log.debug('   - Diffie-Hellman parameters are not %s bits', dhparam_size)
                dhparams = None

        ecparams = context.ecparams
        ecparam_curve = context.spec.ecparam_curve
        if ecparams:
            if force or not ecparam_curve:
                ecparams = None
            elif ecparam_curve and ecparam_curve != get_ecparam_curve(ecparams):
                log.debug('   - Elliptical curve parameters is not %s', ecparam_curve)
                ecparams = None

        if dhparam_size or ecparam_curve:
            # generate params if needed
            if dhparam_size and not dhparams:
                log.info('   - Generating %s bit Diffie-Hellman parameters', dhparam_size)
                dhparams = generate_dhparam(dhparam_size)
            if ecparam_curve and not ecparams:
                log.info('   - Generating %s elliptical curve parameters', ecparam_curve)
                ecparams = generate_ecparam(ecparam_curve)
            context.update(dhparams, ecparams)
        elif context.dhparams or context.ecparams:
            log.debug("   - Removing DH and EC params")
            context.update(None, None)

        if context.params_updated:
            log.debug("   - DH and EC params updated")
        else:
            log.debug("   - DH and EC up to date")

    def update_ocsp(self, context: CertificateContext):
        if not self.fs.directory('ocsp'):
            return

        # ignore ocsp if explicitly disabled for this certificate
        if not context.spec.ocsp_responder_urls:
            return

        log.info(' * OCSP Response')
        for item in context:  # type: CertificateItem
            if not item.certificate:
                log.warning("   - [%s] certificate not found. Can't update OCSP response", item.type.upper())
                continue

            ocsp_response = item.ocsp_response
            if (ocsp_response and ('good' == ocsp_response_status(ocsp_response).lower())
                    and (ocsp_response_serial_number(ocsp_response) == item.certificate.serial_number)):
                last_update = ocsp_response_this_update(ocsp_response)
                log.debug('   - [%s] Have stapled OCSP response updated at %s',
                          item.type.upper(), last_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
            else:
                last_update = None

            ocsp_urls = (item.certificate.ocsp_urls or context.spec.ocsp_responder_urls)
            if not ocsp_urls:
                log.warning('   - [%s] No OCSP responder URL and no default set', item.type.upper())
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
                ocsp_response = fetch_ocsp_response(ocsp_url, ocsp_request, last_update)
                if ocsp_response:
                    if 'successful' != ocsp_response['response_status'].native:
                        log.warning('   - [%s] OCSP request received "%s" from %s', item.type.upper(),
                                    ocsp_response['response_status'].native, ocsp_url)
                        continue

                    ocsp_status = ocsp_response_status(ocsp_response)
                    this_update = ocsp_response_this_update(ocsp_response)
                    log.debug('   - [%s] Retrieved OCSP status "%s" from %s updated at %s', item.type.upper(),
                              ocsp_status.upper(), ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                    if 'good' != ocsp_status.lower():
                        log.warning('   - [%s] certificate has OCSP status "%s" from %s updated at %s', item.type.upper(),
                                    ocsp_status.upper(), ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                        continue

                    if this_update == last_update:
                        log.debug('   - [%s] OCSP response from %s has not been updated', item.type.upper(), ocsp_url)
                        break

                    log.info('   - [%s] Updating OCSP response from %s', item.type.upper(), ocsp_url)
                    item.ocsp_response = ocsp_response
                    break

                elif ocsp_response is False:
                    log.debug('   - [%s] OCSP response from %s has not been updated', item.type.upper(), ocsp_url)
                    break
            else:
                log.warning('   - [%s] Unable to retrieve OCSP response', item.type.upper())

    def update_signed_certificate_timestamps(self, context: CertificateContext):
        if not self.fs.directory('sct'):
            return

        if not context.spec.ct_submit_logs:
            return

        log.info(' * Signed Certificate Timestamps')

        for item in context:  # type: CertificateItem
            if not item.certificate:
                log.warning('   - (%s] certificate not found', item.type.upper())
                continue

            for ct_log in context.spec.ct_submit_logs:  # type: SCTLog
                sct_data = fetch_sct(ct_log, item.certificate, item.chain)
                if sct_data:
                    log.debug('   - [%s] %s has SCT for at %s', item.type.upper(), ct_log.name, _sct_datetime(sct_data.timestamp).isoformat())
                    existing_sct_data, _ = item.sct(ct_log)
                    if sct_data and ((not existing_sct_data) or (sct_data != existing_sct_data)):
                        log.info('   - [%s] Saving Signed Certificate Timestamp from %s', item.type.upper(), ct_log.name)
                        item.update_sct(ct_log, sct_data)

    def apply_changes(self, context: CertificateContext):
        # commit transaction, execute hooks, schedule service reload, …
        transactions = []
        owner = self.config.fileowner()
        hooks = Hooks(self.config.hooks)

        if context.params_updated:
            trx = context.save_params(owner)
            if trx:
                transactions.append(trx)
                if trx.temp_file_path:  # FIXME: archive only transaction support
                    hooks.add('params_installed', certificate_name=context.name, params_file=trx.file_path)

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
                        hooks.add('full_certificate_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)
                else:
                    # FIXME: archive existing file
                    pass

                # Full Key
                trx = item.save_key(owner, with_certificate=True)
                if trx:
                    transactions.append(trx)
                    hooks.add('full_key_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

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

            if item.ocsp_updated:
                trx = item.save_ocsp(owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('ocsp_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path)

            for ct_log in item.spec.ct_submit_logs:
                sct_data, updated = item.sct(ct_log)
                if not updated:
                    continue
                trx = item.save_sct(ct_log.name, owner)
                if trx:
                    transactions.append(trx)
                    hooks.add('sct_installed', certificate_name=item.name, key_type=item.type, file=trx.file_path, ct_log_name=ct_log.name)
        if transactions:
            try:
                commit_file_transactions(transactions, self.fs.archive_dir(context.name))
                self.update_services(context.spec.services)
                hooks.call()
            except Exception as e:
                raise AcmeError('[{}] Unable to install keys and certificates', context.name) from e

    def finalize(self):
        linker = actions.LinkAction(self.config, self.fs, self.args, None)
        for context in self._done:
            try:
                linker.run(context.spec)
            except AcmeError as e:
                log.error("[%s] links update error: %s", context.name, str(e))

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
                try:
                    verify_certificate_installation(context, max_ocsp_verify_attempts, ocsp_verify_retry_delay)
                except AcmeError as e:
                    log.error("[%s] validation error: %s", context.name, str(e))

    def update_services(self, services: Iterable[str]):
        if services:
            self._services.update(services)

    def _reload_services(self) -> bool:
        reloaded = False
        for service_name in self._services:
            service_command = self.config.service(service_name)
            if service_command:
                log.info('Reloading service %s', service_name)
                try:
                    output = subprocess.check_output(service_command, shell=True, stderr=subprocess.STDOUT)
                    reloaded = True
                    if output:
                        log.info('Service "%s" responded to reload with:\n%s', service_name, output)
                except subprocess.CalledProcessError as error:
                    log.warning('Service "%s" reload failed, code: %s:\n%s', service_name, error.returncode, error.output)
            else:
                log.error('Service %s does not have registered reload command', service_name)
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

        action = subparsers.add_parser('check', help='check installed files permissions')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.CheckAction)

        action = subparsers.add_parser('revoke', help='revoke certificates')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.RevokeAction)

        action = subparsers.add_parser('auth', help='perform domain authentification')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.AuthAction)

        action = subparsers.add_parser('link', help='update certificates symlinks')
        action.add_argument('certificate_names', nargs='*')
        action.set_defaults(cls=actions.LinkAction)

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

        # action.add_argument('--fast-dhparams',
        #                        action='store_true', dest='fast_dhparams', default=False,
        #                        help='Using 2ton.com.au online generator to get dhparams instead of generating them locally')

        # # Misc options
        # argparser.add_argument('--export-client',
        #                        dest='export_key_path', default=False, help='Export client key')
        #

        self.args = argparser.parse_args()

        # reset root logger
        for handler in list(log.handlers):
            log.removeHandler(handler)
        # create console handler
        stream = StreamHandler(sys.stderr)
        # enable color output
        if sys.stderr.isatty() and self.args.color and not self.args.no_color:
            stream.setFormatter(ColorFormatter())
        log.addHandler(stream)

        if self.args.quiet:
            log.setLevel(logging.ERROR)
        elif self.args.debug:
            log.setLevel(logging.DEBUG)
        elif self.args.verbose:
            log.setLevel(logging.INFO)
        else:
            log.setLevel(logging.WARNING)

        self.config, self.fs = Configuration.load(self.args.config_path, ('.', os.path.join('/etc', self.script_name), self.script_dir))
        if not self.config.get('color_output'):
            # Reset formatter in case we don't want color
            stream.setFormatter(logging.Formatter())

    # def export_client_key(self, path: str):
    #     log.debug("exporting client key")
    #     client_key = self.acme_client.net.key
    #     client_key_pem = client_key.key.private_bytes(
    #         encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    #     try:
    #         with open(path, 'wb') as f:
    #             f.write(client_key_pem)
    #             logging.info('Client key exported to "%s"', path)
    #     except Exception as error:
    #         logging.error('Unbale to write client key to "%s": %s', path, str(error))

    def connect_client(self) -> client.ClientV2:
        resource_dir = os.path.join(self.script_dir, self.fs.directory('resource'))
        archive_dir = self.fs.archive_dir('client')
        return acme.connect_client(resource_dir, self.config.account['email'], self.config.get('acme_directory_url'), archive_dir)

    def run(self):
        log.info('\n----- %s executed at %s', self.script_name, str(datetime.datetime.now()))
        pid_file_path = os.path.join(self.fs.directory('pid'), self.script_name + '.pid')
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
            if process_running(pid_file_path):
                log.debug('Waiting for other running client instance')
                while process_running(pid_file_path):
                    time.sleep(random.randrange(5, 30))
        else:
            if process_running(pid_file_path):
                log.error('Client already running')
        with open_file(pid_file_path, 'w') as pid_file:
            pid_file.write(str(os.getpid()))
        try:
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
                    action.run(cert)
                except AcmeError as e:
                    log.error("[%s] processing failed. No files updated\n%s", cert.name, str(e))
                    if self.args.debug:
                        traceback.print_exc()
                else:
                    action.finalize()
        finally:
            os.remove(pid_file_path)


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
