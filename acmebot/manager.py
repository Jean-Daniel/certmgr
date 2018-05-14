import abc
import argparse
import datetime
import json
import logging
import os
import random
import shutil
import stat
import subprocess
import sys
import time
import urllib
from argparse import Namespace
from logging import StreamHandler
from typing import Optional, Iterable
from urllib import parse

import OpenSSL
import josepy
import pkg_resources
from acme import client, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import log, AcmeError
from .acme import handle_authorizations
from .config import FileManager, Configuration, CertificateSpec
from .context import CertificateContext
from .crypto import PrivateKey
from .utils import Hooks, FileTransaction, commit_file_transactions, makedir, open_file, ColorFormatter, process_running


class Action(metaclass=abc.ABCMeta):
    has_acme_client = True

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client: Optional[client.ClientV2]):
        self.config = config
        self.fs = fs
        self.args = args
        self.acme_client = acme_client
        assert (not self.has_acme_client) or acme_client

    @abc.abstractmethod
    def run(self, certificate: CertificateSpec):
        raise NotImplementedError()

    def finalize(self):
        pass


class CheckAction(Action):
    has_acme_client = False

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client):
        super().__init__(config, fs, args, acme_client)
        self.owner = config.fileowner()

    def _check_file(self, name, file: str, mode: int):
        if not os.path.exists(file):
            return

        s = os.stat(file, follow_symlinks=False)
        if stat.S_IMODE(s.st_mode) != mode:
            log.info('[%s] file permission should be %s not %s', name, mode, stat.S_IMODE(s.st_mode))
            os.chmod(file, mode)

        if s.st_uid != self.owner.uid or s.st_gid != self.owner.gid:
            log.info('[%s] file owner/group should be %s/%s not %s/%s', name, self.owner.uid, self.owner.gid, s.st_uid, s.st_gid)
            os.chown(file, self.owner.uid, self.owner.gid)

    def run(self, certificate: CertificateSpec):
        log.debug('[%s] checking installed files', certificate.name)

        self._check_file(certificate.name, self.fs.filepath('param', certificate.name), 0o644)

        for key_type in certificate.key_types:
            # Private Keys
            self._check_file(certificate.name, self.fs.filepath('private_key', certificate.name, key_type), 0o640)
            self._check_file(certificate.name, self.fs.filepath('full_key', certificate.name, key_type), 0o640)

            # Certificate
            self._check_file(certificate.name, self.fs.filepath('certificate', certificate.name, key_type), 0o644)
            self._check_file(certificate.name, self.fs.filepath('chain', certificate.name, key_type), 0o644)
            self._check_file(certificate.name, self.fs.filepath('full_certificate', certificate.name, key_type), 0o644)

            # OCSP
            self._check_file(certificate.name, self.fs.filepath('ocsp', certificate.name, key_type), 0o644)

            for ct_log_name in certificate.ct_submit_logs:
                self._check_file(certificate.name, self.fs.filepath('sct', certificate.name, key_type, ct_log_name=ct_log_name), 0o644)


class RevokeAction(Action):

    def run(self, certificate: CertificateSpec):
        certificate_count = 0
        revoked_certificates = []
        context = CertificateContext(certificate, self.fs)
        for item in context:
            cert = item.certificate
            if cert:
                certificate_count += 1
                try:
                    log.debug('[%s:%s] revoking certificate', certificate.name, item.type.upper())
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.encode())
                    self.acme_client.revoke(josepy.ComparableX509(x509), 0)
                    revoked_certificates.append(item)
                    log.info('[%s:%s] certificate revoked', certificate.name, item.type.upper())
                except Exception as error:
                    log.warning('[%s:%s] Failed to revoke certificate: %s', certificate.name, item.type.upper(), str(error))
            else:
                log.warning('[%s:%s] certificate not found', certificate.name, item.type.upper())

        archive_date = datetime.datetime.now()
        context.archive_file('param', archive_date)
        for item in revoked_certificates:
            item.archive_file('certificate', archive_date)
            item.archive_file('chain', archive_date)
            item.archive_file('full_certificate', archive_date)

            item.archive_file('private_key', archive_date)
            item.archive_file('full_key', archive_date)

            item.archive_file('oscp', archive_date)
            for ct_log_name in certificate.ct_submit_logs:
                item.archive_file('sct', archive_date, ct_log_name=ct_log_name)


class AuthAction(Action):
    def run(self, certificate: CertificateSpec):
        context = CertificateContext(certificate, self.fs)
        # until acme provide a clean way to create an order without using a CSR, we just create a dummy CSR …
        key = PrivateKey.create('rsa', 2048)
        csr = key.create_csr(context.spec.common_name, context.spec.alt_names, context.spec.ocsp_must_staple)
        order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
        # … and remove it from the order afterward
        order.update(csr_pem=None)

        handle_authorizations(order, self.fs, self.acme_client,
                              self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'))


class LinkAction(Action):
    has_acme_client = False

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client):
        super().__init__(config, fs, args, acme_client)
        self.root = fs.directory('symlinks')

    def process_symlink(self, name: str, target: str, link: str):
        link_path = os.path.join(self.root, name, link)
        if os.path.exists(target):
            try:
                if os.readlink(link_path) == target:
                    return
                os.remove(link_path)
            except FileNotFoundError:
                pass
            log.debug("symlink '%s' -> '%s' created", link_path, target)
            os.symlink(target, link_path)
        else:
            try:
                os.remove(link_path)
                log.debug("symlink '%s' removed", link_path)
            except FileNotFoundError:
                pass

    def run(self, certificate: CertificateSpec):
        if not self.root:
            return

        log.debug('Update symlinks for %s', certificate.name)

        # Create main target directory
        os.makedirs(os.path.join(self.root, certificate.common_name), mode=0o755, exist_ok=True)

        target = self.fs.filepath('param', certificate.name)
        self.process_symlink(certificate.common_name, target, 'params.pem')

        for key_type in certificate.key_types:
            # Private Keys
            target = self.fs.filepath('private_key', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, key_type + '.key')

            target = self.fs.filepath('full_key', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, 'full.' + key_type + '.key')

            # Certificate
            target = self.fs.filepath('certificate', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, 'cert.' + key_type + '.pem')

            target = self.fs.filepath('chain', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, 'chain.' + key_type + '.pem')

            target = self.fs.filepath('full_certificate', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, 'cert+root.' + key_type + '.pem')

            # OCSP
            target = self.fs.filepath('ocsp', certificate.name, key_type)
            self.process_symlink(certificate.common_name, target, key_type + '.ocsp')

            for ct_log_name in certificate.ct_submit_logs:
                target = self.fs.filepath('sct', certificate.name, key_type, ct_log_name=ct_log_name)
                self.process_symlink(certificate.common_name, target, ct_log_name + '.' + key_type + '.sct')

        for name in certificate.alt_names:
            if name == certificate.common_name:
                continue
            link_path = os.path.join(self.root, name)
            if os.path.islink(link_path):
                if os.readlink(link_path) != certificate.common_name:
                    os.remove(link_path)
                else:
                    continue
            elif os.path.isdir(link_path):
                log.debug("removing existing directory")
                shutil.rmtree(link_path)

            os.symlink(certificate.common_name, link_path)
            log.debug("symlink '%s' -> '%s' created", link_path, certificate.common_name)


class VerifyAction(Action):

    def run(self, certificate: CertificateSpec):
        pass


class UpdateAction(Action):

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client: client.ClientV2):
        super().__init__(config, fs, args, acme_client)
        self._done = []
        self._services = set()

    def run(self, certificate: CertificateSpec):
        pass

    def finalize(self):
        if self.args.link:
            linker = LinkAction(self.config, self.fs, self.args, None)
            for context in self._done:
                try:
                    linker.run(context.spec)
                except AcmeError as e:
                    log.error("[%s] links update error: %s", context.name, str(e))

        # Call hook usefull to sync status with other hosts
        updated = [context.name for context in self._done if context.updated]
        if updated:
            hooks = Hooks()
            hooks.add('certificates_updated', self.config.hook('certificates_updated'), certificates=json.dumps(sorted(updated)))
            hooks.call()

        if self._reload_services() and self.args.verify:
            log.info("Waiting service reload before verifying")
            time.sleep(5)  # allow time for services to reload before verification

        if self.args.verify:
            verify = VerifyAction(self.config, self.fs, self.args, self.acme_client)
            for context in self._done:
                try:
                    verify.run(context.spec)
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
        self.script_version = '3.0.0'

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
        action.set_defaults(cls=CheckAction)

        action = subparsers.add_parser('revoke', help='revoke certificates')
        action.set_defaults(cls=RevokeAction)

        action = subparsers.add_parser('auth', help='perform domain authentification')
        action.set_defaults(cls=AuthAction)

        action = subparsers.add_parser('link', help='update certificates symlinks')
        action.set_defaults(cls=LinkAction)

        action = subparsers.add_parser('update', help='update keys, certificates, oscp, sct and params')
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

        action.add_argument('--link',
                            action='store_true', dest='link', default=True,
                            help='Create symlink after update')
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

        # All subcommands take an optional list of certificate anme
        argparser.add_argument('certificate_names', nargs='*')

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

    # def _rename_file(self, old_file_path, new_file_path, chmod=None, timestamp=None):
    #     return rename_file(old_file_path, new_file_path, chmod, self.config.get('file_user'), self.config.get('file_group'), timestamp)
    #

    # def update_certificate(self, certificate_name: str):
    #     self.updated_certificates.add(certificate_name)
    #
    # def update_services(self, services):
    #     if services:
    #         self.updated_services.update(services)
    #
    # def reload_services(self):
    #     reloaded = False
    #     for service_name in self.updated_services:
    #         service_command = self.config.service(service_name)
    #         if service_command:
    #             log.info('Reloading service %s', service_name)
    #             try:
    #                 output = subprocess.check_output(service_command, shell=True, stderr=subprocess.STDOUT)
    #                 reloaded = True
    #                 if output:
    #                     log.info('Service "%s" responded to reload with:\n%s', service_name, output)
    #             except subprocess.CalledProcessError as error:
    #                 log.warning('Service "%s" reload failed, code: %s:\n%s', service_name, error.returncode, error.output)
    #         else:
    #             log.error('Service %s does not have registered reload command', service_name)
    #     return reloaded
    #
    # def save_private_key(self, file_type, file_name, key_type, private_key, key_cipher_data,
    #                      timestamp=None, certificate=None, chain=None, dhparam_pem=None, ecparam_pem=None):
    #     with FileTransaction(file_type, self.fs.filepath(file_type, file_name, key_type), chmod=0o640, timestamp=timestamp) as transaction:
    #         if private_key:
    #             if key_cipher_data and not key_cipher_data.forced:
    #                 try:
    #                     key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key, key_cipher_data.cipher,
    #                                                              key_cipher_data.passphrase.encode('utf-8'))
    #                 except Exception as e:
    #                     raise PrivateKeyError(file_name) from e
    #             else:
    #                 key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    #             transaction.write(key_pem.decode('ascii'))
    #             if certificate:
    #                 transaction.write('\n')
    #                 save_certificate(transaction, certificate, chain=chain, dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
    #     return transaction
    #
    # def archive_private_key(self, file_type, file_name, key_type, archive_name='', archive_date=None):
    #     self._archive_file(file_type, self.fs.filepath(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)
    #
    # def load_root_certificates(self):
    #     root_certificates = collections.OrderedDict()
    #     for key_type in SUPPORTED_KEY_TYPES:
    #         root_certificates[key_type] = self.load_certificate(os.path.join(os.path.dirname(self.config.path), 'root_cert'), key_type)
    #     return root_certificates
    #
    # def save_certificate(self, file_type, file_name, key_type, certificate, chain=None, root_certificate=None, dhparam_pem=None, ecparam_pem=None):
    #     with FileTransaction(file_type, self.fs.filepath(file_type, file_name, key_type), chmod=0o644) as transaction:
    #         save_certificate(transaction.file, certificate, chain=chain, root_certificate=root_certificate, dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
    #     return transaction
    #
    # def archive_certificate(self, file_type, file_name, key_type, archive_name='', archive_date=None):
    #     self._archive_file(file_type, self.fs.filepath(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)
    #
    # def load_chain(self, file_name, key_type):
    #     chain = []
    #     try:
    #         pem_data = None
    #         if self.fs.directory('chain'):
    #             chain_file_path = self.fs.filepath('chain', file_name, key_type)
    #             if os.path.isfile(chain_file_path):
    #                 with open(chain_file_path) as chain_file:
    #                     pem_data = chain_file.read()
    #                     index = 0
    #         if not pem_data:
    #             with open(self.fs.filepath('certificate', file_name, key_type)) as certificate_file:
    #                 pem_data = certificate_file.read()
    #                 index = 1
    #         certificate_pems = re.findall('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem_data, re.DOTALL)[index:]
    #         for certificate_pem in certificate_pems:
    #             chain.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_pem.encode('ascii')))
    #     except Exception as e:
    #         log.warning("error loading chain: %s", str(e))
    #     return chain
    #
    # def save_chain(self, file_name, key_type, chain):
    #     with FileTransaction('chain', self.fs.filepath('chain', file_name, key_type), chmod=0o644) as transaction:
    #         save_chain(transaction.file, chain)
    #     return transaction
    #
    # def archive_chain(self, file_name, key_type, archive_name='', archive_date=None):
    #     self._archive_file('chain', self.fs.filepath('chain', file_name, key_type), archive_name=archive_name, archive_date=archive_date)
    #
    # def params_present(self, file_name, dhparam_pem, ecparam_pem):
    #     param_file_path = self.fs.filepath('param', file_name)
    #     if os.path.isfile(param_file_path):
    #         with open(param_file_path, 'r') as param_file:
    #             params = param_file.read()
    #             return ((not dhparam_pem) or (dhparam_pem in params)) and ((not ecparam_pem) or (ecparam_pem in params))
    #     return False
    #
    # def save_params(self, file_name, dhparam_pem, ecparam_pem):
    #     with FileTransaction('param', self.fs.filepath('param', file_name), chmod=0o640) as transaction:
    #         if dhparam_pem and ecparam_pem:
    #             transaction.write(dhparam_pem + '\n' + ecparam_pem)
    #         else:
    #             transaction.write(dhparam_pem or ecparam_pem)
    #     return transaction
    #
    # @staticmethod
    # def _sct_datetime(sct_timestamp):
    #     return datetime.datetime.utcfromtimestamp(sct_timestamp / 1000)
    #
    # def fetch_sct(self, ct_log_name, certificate, chain):
    #     ct_log = self.config.ct_log(ct_log_name)
    #     if ct_log and ('url' in ct_log):
    #         certificates = ([base64.b64encode(certificate_bytes(certificate)).decode('ascii')]
    #                         + [base64.b64encode(certificate_bytes(chain_certificate)).decode('ascii') for chain_certificate in chain])
    #         request_data = json.dumps({'chain': certificates}).encode('ascii')
    #         request = urllib.request.Request(url=ct_log['url'] + '/ct/v1/add-chain', data=request_data)
    #         request.add_header('Content-Type', 'application/json')
    #         try:
    #             with urllib.request.urlopen(request) as response:
    #                 sct = json.loads(response.read().decode('utf-8'))
    #                 return SCTData(sct.get('sct_version'), sct.get('id'), sct.get('timestamp'), sct.get('extensions'), sct.get('signature'))
    #         except urllib.error.HTTPError as error:
    #             if (400 <= error.code) and (error.code < 500):
    #                 log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)\n%s', ct_log_name, error.code, error.reason, error.read())
    #             else:
    #                 log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)', ct_log_name, error.code, error.reason)
    #         except urllib.error.URLError as error:
    #             log.warning('Unable to retrieve SCT from log %s: %s', ct_log_name, error.reason)
    #         except Exception as error:
    #             log.warning('Unable to retrieve SCT from log %s: %s', ct_log_name, str(error))
    #     else:
    #         log.warning('Unknown CT log: %s', ct_log_name)
    #     return None
    #
    # def load_sct(self, file_name, key_type, ct_log_name):
    #     try:
    #         ct_log = self.config.ct_log(ct_log_name)
    #         if ct_log and ('id' in ct_log):
    #             sct_file_path = self.fs.filepath('sct', file_name, key_type, ct_log_name=ct_log_name)
    #             with open(sct_file_path, 'rb') as sct_file:
    #                 sct = sct_file.read()
    #                 version, logid, timestamp, extensions_len = struct.unpack('>b32sQH', sct[:43])
    #                 logid = base64.b64encode(logid).decode('ascii')
    #                 extensions = base64.b64encode(sct[43:(43 + extensions_len)]).decode('ascii') if extensions_len else ''
    #                 signature = base64.b64encode(sct[43 + extensions_len:]).decode('ascii')
    #
    #                 if ct_log['id'] == logid:
    #                     return SCTData(version, logid, timestamp, extensions, signature)
    #                 else:
    #                     log.debug('SCT "%s" does not match log id for "%s"', sct_file_path, ct_log_name)
    #     except Exception as e:
    #         log.warning("error loading sct log: %s", str(e))
    #     return None
    #
    # def save_sct(self, file_name, key_type, ct_log_name, sct_data):
    #     ct_log = self.config.ct_log(ct_log_name)
    #     if ct_log:
    #         with FileTransaction('sct', self.fs.filepath('sct', file_name, key_type, ct_log_name=ct_log_name), chmod=0o640, mode='wb') as transaction:
    #             extensions = base64.b64decode(sct_data.extensions)
    #             sct = struct.pack('>b32sQH', sct_data.version, base64.b64decode(sct_data.id), sct_data.timestamp, len(extensions))
    #             sct += extensions + base64.b64decode(sct_data.signature)
    #             transaction.write(sct)
    #         return transaction
    #     return None
    #
    # def archive_sct(self, file_name, key_type, ct_log_name, archive_name='', archive_date=None):
    #     self._archive_file('sct', self.fs.filepath('sct', file_name, key_type, ct_log_name=ct_log_name), archive_name=archive_name,
    #                        archive_date=archive_date)
    #
    # def load_oscp_response(self, file_name, key_type):
    #     return load_ocsp_response(self.fs.filepath('ocsp', file_name, key_type))
    #
    # def save_ocsp_response(self, file_name, key_type, ocsp_response):
    #     with FileTransaction('ocsp', self.fs.filepath('ocsp', file_name, key_type), chmod=0o640, mode='wb') as transaction:
    #         transaction.write(ocsp_response.dump())
    #     return transaction

    def _user_agent(self):
        return '{script}/{version} acme-python/{acme_version}'.format(script=self.script_name, version=self.script_version,
                                                                      acme_version=pkg_resources.get_distribution('acme').version)

    @staticmethod
    def _generate_client_key():
        return josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend()))

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
        makedir(resource_dir, 0o600)
        generated_client_key = False
        client_key_path = os.path.join(resource_dir, 'client_key.json')
        try:
            with open(client_key_path) as f:
                client_key = josepy.JWKRSA.fields_from_json(json.load(f))
            log.debug('Loaded client key %s', client_key_path)
        except FileNotFoundError:
            log.info('Client key not present, generating')
            client_key = self._generate_client_key()
            generated_client_key = True

        registration = None
        registration_path = os.path.join(resource_dir, 'registration.json')
        try:
            with open(registration_path) as f:
                registration = messages.RegistrationResource.json_loads(f.read())
                log.debug('Loaded registration %s', registration_path)
                acme_url = urllib.parse.urlparse(self.config.get('acme_directory_url'))
                reg_url = urllib.parse.urlparse(registration.uri)
                if (acme_url[0] != reg_url[0]) or (acme_url[1] != reg_url[1]):
                    log.info('ACME service URL has changed, re-registering with new client key')
                    registration = None
                    # ACME-ISSUE Resetting the client key should not be necessary, but the new registration comes back empty if we use the old key
                    client_key = self._generate_client_key()
                    generated_client_key = True
        except FileNotFoundError:
            pass

        try:
            net = client.ClientNetwork(client_key, account=registration, user_agent=self._user_agent())
            log.debug("Fetching meta from acme server '%s'", self.config.get('acme_directory_url'))
            directory = messages.Directory.from_json(net.get(self.config.get('acme_directory_url')).json())
            acme_client = client.ClientV2(directory, net)
        except Exception as error:
            raise AcmeError("Can't connect to ACME service") from error

        if registration:
            return acme_client

        log.info('Registering client')
        try:
            reg = messages.NewRegistration.from_data(email=self.config.account['email'])
            if "terms_of_service" in acme_client.directory.meta:
                tos = acme_client.directory.meta.terms_of_service
                if sys.stdin.isatty():
                    sys.stdout.write('ACME service has the following terms of service:\n')
                    sys.stdout.write(tos)
                    sys.stdout.write('\n')
                    answer = input('Accept? (Y/n) ')
                    if answer and not answer.lower().startswith('y'):
                        raise Exception('Terms of service rejected.')
                    log.debug('Terms of service accepted.')
                else:
                    log.debug('Terms of service auto-accepted: %s', tos)
                reg = reg.update(terms_of_service_agreed=True)

            registration = acme_client.new_account(reg)
        except Exception as error:
            raise AcmeError("Can't register with ACME service") from error

        transactions = []
        if generated_client_key:
            with FileTransaction('client', client_key_path, chmod=0o600, mode='w') as client_key_transaction:
                client_key_transaction.write(json.dumps(client_key.fields_to_partial_json()))
                client_key_transaction.message = 'Saved client key'
                transactions.append(client_key_transaction)

        with FileTransaction('registration', registration_path, chmod=0o600, mode='w') as registration_transaction:
            registration_transaction.write(registration.json_dumps())
            registration_transaction.message = 'Saved registration'
            transactions.append(registration_transaction)
        try:
            commit_file_transactions(transactions, self.fs.archive_dir('client'))
        except Exception as e:
            raise AcmeError('Unable to save registration to {}', registration_path) from e

        return acme_client

    # def _handle_authorizations(self, order: messages.OrderResource, fetch_only: bool) -> List[messages.AuthorizationResource]:
    #     return handle_authorizations(order, self.fs, self.acme_client, fetch_only,
    #                                  self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'))
    #
    # def process_authorizations(self, context: CertificateContext):
    #     auth_only = self.config.get('mode') == 'master'
    #     for item in context:
    #         order = item.order(self.acme_client, auth_only)
    #         authorizations = self._handle_authorizations(order, False)
    #         # In master mode, no need to process all certificates
    #         if auth_only:
    #             break

    #    def _poll_order(self, order):
    #        response = self.acme_client.net.get(order.uri)
    #        body = messages.Order.from_json(response.json())
    #        if body.error is not None:
    #            raise body.error
    #        return order.update(body=body), response

    # def _generate_dhparam(self, dhparam_size: int, dhparam_idx: int):
    #     if self.args.fast_dhparams:
    #         return fetch_dhparams(dhparam_size, dhparam_idx)
    #     return generate_dhparam(dhparam_size)
    #
    # def process_certificates(self, context: CertificateContext):
    #     # count of certs used as an index to get fast dhparams
    #     # dhparam_idx = len(self.config.certificates)
    #
    #     # key_cipher_data = self.key_cipher_data(certificate_name)
    #
    #     log.debug('Processing certificate %s', context.name)
    #
    #     # if we do not force refresh params
    #     if self.args.rollover:
    #         context.reset_params()
    #
    #     # For each types, check if the cert exists and is valid (params match and not about to expire)
    #     for item in context:  # type: CertificateItem
    #         if self.args.renew or item.should_renew(self.config.int('renewal_days')):
    #             log.info('Generating primary %s key for %s', key_type.upper(), certificate_name)
    #             cert_item.key = generate_private_key(key_type, cert_spec.private_key.params(key_type))
    #             if not cert_item.key:
    #                 raise AcmeError("{} private key generation failed for certificate {}", key_type.upper(), certificate_name)
    #
    #             csr_pem = generate_csr(cert_item.key, cert_spec.common_name, cert_spec.alt_names, cert_spec.ocsp_must_staple)
    #             log.info('Requesting %s certificate for %s%s', key_type.upper(), cert_spec.common_name,
    #                      (' with alt names: ' + ', '.join(cert_spec.alt_names)) if cert_spec.alt_names else '')
    #             try:
    #                 order = self.acme_client.new_order(csr_pem)
    #                 self._handle_authorizations(order, auth_fetch_only)
    #                 if order.uri:
    #                     order, response = self._poll_order(order)
    #                     if messages.STATUS_INVALID == order.body.status:
    #                         raise AcmeError('Unable to issue {} certificate {}', key_type.upper(), certificate_name)
    #                 order = self.acme_client.finalize_order(order, datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('cert_poll_time')))
    #                 cert_item.certificate, cert_item.chain = decode_full_chain(order.fullchain_pem)
    #             except Exception as e:
    #                 raise AcmeError('{} certificate issuance failed: {}', key_type.upper(), str(e)) from e
    #
    #             log.debug('New %s certificate issued', key_type.upper())
    #             cert_data.params = CertParams(None, None)
    #             cert_item.updated = True
    #
    #     # Updating dhparams
    #     dhparam_size = cert_spec.dhparam_size
    #     if cert_data.params.dhparams and dhparam_size and (dhparam_size != get_dhparam_size(cert_data.params.dhparams)):
    #         log.info('Diffie-Hellman parameters for %s are not %s bits', certificate_name, dhparam_size)
    #         cert_data.params.dhparams = None
    #     # Remove existing params
    #     if cert_data.params.dhparams and not dhparam_size:
    #         cert_data.params.dhparams = None
    #         cert_data.params_updated = True
    #     elif (not cert_data.params.dhparams) and dhparam_size:
    #         log.info('Generating Diffie-Hellman parameters for %s', certificate_name)
    #         cert_data.params.dhparams = self._generate_dhparam(dhparam_size, dhparam_idx)
    #         if not cert_data.params.dhparams:
    #             raise AcmeError('Diffie-Hellman parameters generation failed for {} bits', dhparam_size)
    #         cert_data.params_updated = True
    #     dhparam_idx -= 1
    #
    #     # Updating ecparams
    #     ecparam_curve = cert_spec.ecparam_curve
    #     if cert_data.params.ecparams and ecparam_curve and (ecparam_curve != get_ecparam_curve(cert_data.params.ecparams)):
    #         log.info('Elliptical curve parameters for %s are not curve %s', certificate_name, ecparam_curve)
    #         cert_data.params.ecparams = None
    #     # Remove existing params
    #     if cert_data.params.ecparams and not ecparam_curve:
    #         cert_data.params.ecparams = None
    #         cert_data.params_updated = True
    #     elif (not cert_data.params.ecparams) and ecparam_curve:
    #         log.info('Generating elliptical curve parameters for %s', certificate_name)
    #         cert_data.params.ecparams = generate_ecparam(ecparam_curve)
    #         if not cert_data.params.ecparams:
    #             raise AcmeError('Elliptical curve parameters generation failed for curve {}', ecparam_curve)
    #         cert_data.params_updated = True
    #
    #     self.install_certificate(cert_data)
    #
    # def install_certificate(self, certificate: CertificateContext):
    #     # install keys and certificates
    #     root_certificates = self.load_root_certificates()
    #
    #     certificate_name = certificate.name
    #     cert_spec = certificate.spec
    #
    #     transactions = []
    #
    #     # dh and ec params
    #     dhparams = certificate.params.dhparams
    #     ecparams = certificate.params.ecparams
    #
    #     if certificate.params_updated and self.fs.directory('param'):
    #         if dhparams or ecparams:
    #             transactions.append(self.save_params(certificate_name, certificate.params.dhparams, certificate.params.ecparams))
    #             self._add_hook('params_installed', key_name=certificate_name, certificate_name=certificate_name,
    #                            params_file=self.fs.filepath('param', certificate_name))
    #         else:
    #             # TODO: remove old params
    #             pass
    #
    #     # save private keys
    #     key_cipher_data = self.key_cipher_data(certificate_name)
    #     for key_type, cert_item in certificate._items.items():
    #         if cert_item.updated or certificate.params_updated:
    #             transactions.append(self.save_certificate('certificate', certificate_name, key_type, cert_item.certificate,
    #                                                       chain=cert_item.chain, dhparam_pem=dhparams, ecparam_pem=ecparams))
    #             self._add_hook('certificate_installed', certificate_name=certificate_name, key_type=key_type,
    #                            certificate_file=self.fs.filepath('certificate', certificate_name, key_type))
    #
    #         if self.fs.directory('full_certificate'):
    #             full_cert_file = self.fs.filepath('full_certificate', certificate_name, key_type)
    #             exists = os.path.exists(full_cert_file)
    #             if root_certificates[key_type] and (not exists or cert_item.updated or certificate.params_updated):
    #                 transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, cert_item.certificate,
    #                                                           chain=cert_item.chain, root_certificate=root_certificates[key_type],
    #                                                           dhparam_pem=dhparams, ecparam_pem=ecparams))
    #                 self._add_hook('full_certificate_installed', certificate_name=certificate_name, key_type=key_type, full_certificate_file=full_cert_file)
    #             elif exists and not root_certificates[key_type]:
    #                 # TODO: remove existing full certificate
    #                 pass
    #
    #         if self.config.directory('chain') and cert_item.updated:
    #             transactions.append(self.save_chain(certificate_name, key_type, cert_item.chain))
    #             self._add_hook('chain_installed', certificate_name=certificate_name, key_type=key_type,
    #                            chain_file=self.fs.filepath('chain', certificate_name, key_type))
    #
    #         if cert_item.updated:
    #             transactions.append(self.save_private_key('private_key', certificate_name, key_type, cert_item.key, key_cipher_data))
    #             self._add_hook('private_key_installed', certificate_name=certificate_name, key_type=key_type,
    #                            private_key_file=self.fs.filepath('private_key', certificate_name, key_type),
    #                            passphrase=key_cipher_data.passphrase if key_cipher_data else None)
    #
    #         if self.fs.directory('full_key') and (cert_item.updated or certificate.params_updated):
    #             transactions.append(self.save_private_key('full_key', certificate_name, key_type, cert_item.key, key_cipher_data,
    #                                                       certificate=cert_item.certificate, chain=cert_item.chain,
    #                                                       dhparam_pem=dhparams, ecparam_pem=ecparams))
    #             self._add_hook('full_key_installed', certificate_name=certificate_name, key_type=key_type,
    #                            full_key_file=self.fs.filepath('full_key', certificate_name, key_type))
    #
    #     if transactions:
    #         try:
    #             self._commit_file_transactions(transactions, archive_name=certificate_name)
    #             self._call_hooks()
    #
    #             updated = False
    #             for key_type, cert_item in certificate._items.items():
    #                 if cert_item.updated:
    #                     log.info('%s private keys and certificate for %s installed', key_type.upper(), certificate_name)
    #                     updated = True
    #
    #             if updated:
    #                 self.update_services(cert_spec.services)
    #                 self.update_certificate(certificate_name)
    #
    #         except Exception as error:
    #             log.warning('Unable to install keys and certificates for %s: %s', certificate_name, str(error))
    #             self._clear_hooks()
    #
    # def update_signed_certificate_timestamps(self, certificates_names):
    #     if not self.fs.directory('sct'):
    #         return
    #
    #     for certificate_name, cert_spec in self.config.certificates.items():
    #         if certificates_names and (certificate_name not in certificates_names):
    #             continue
    #
    #         if not cert_spec.ct_submit_logs:
    #             continue
    #
    #         transactions = []
    #         for key_type in cert_spec.key_types:
    #             certificate = self.load_certificate(certificate_name, key_type)
    #             if not certificate:
    #                 log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
    #                 continue
    #
    #             chain = self.load_chain(certificate_name, key_type)
    #             for ct_log_name in cert_spec.ct_submit_logs:
    #                 sct_data = self.fetch_sct(ct_log_name, certificate, chain)
    #                 if sct_data:
    #                     log.debug('%s has SCT for %s certificate %s at %s', ct_log_name, key_type.upper(),
    #                               certificate_name, self._sct_datetime(sct_data.timestamp).isoformat())
    #                     existing_sct_data = self.load_sct(certificate_name, key_type, ct_log_name)
    #                     if sct_data and ((not existing_sct_data) or (sct_data != existing_sct_data)):
    #                         log.info('Saving Signed Certificate Timestamp for %s certificate %s from %s', key_type.upper(), certificate_name,
    #                                  ct_log_name)
    #                         transactions.append(self.save_sct(certificate_name, key_type, ct_log_name, sct_data))
    #                         self._add_hook('sct_installed', certificate_name=certificate_name, key_type=key_type, ct_log_name=ct_log_name,
    #                                        sct_file=self.fs.filepath('sct', certificate_name, key_type, ct_log_name=ct_log_name))
    #         if transactions:
    #             try:
    #                 self._commit_file_transactions(transactions, archive_name=None)
    #                 self._call_hooks()
    #
    #                 self.update_services(cert_spec.services)
    #                 self.update_certificate(certificate_name)
    #             except Exception as error:
    #                 log.warning('Unable to save Signed Certificate Timestamps for %s: %s', certificate_name, str(error))
    #                 self._clear_hooks()
    #
    # def update_ocsp_responses(self, certificate_names):
    #     if not self.config.directory('ocsp'):
    #         return
    #
    #     root_certificates = self.load_root_certificates()
    #
    #     for certificate_name, cert_spec in self.config.certificates.items():
    #         if certificate_names and (certificate_name not in certificate_names):
    #             continue
    #
    #         # ignore ocsp if explicitly disabled for this certificate
    #         if not cert_spec.ocsp_responder_urls:
    #             continue
    #
    #         transactions = []
    #         for key_type in cert_spec.key_types:
    #             certificate = self.load_certificate(certificate_name, key_type)
    #             if not certificate:
    #                 log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
    #                 continue
    #
    #             asn1crypto_certificate = asn1_x509.Certificate.load(certificate_bytes(certificate))
    #             ocsp_response = self.load_oscp_response(certificate_name, key_type)
    #             if (ocsp_response and ('good' == ocsp_response_status(ocsp_response).lower())
    #                     and (ocsp_response_serial_number(ocsp_response) == asn1crypto_certificate.serial_number)):
    #                 last_update = ocsp_response_this_update(ocsp_response)
    #                 log.debug('Have stapled OCSP response for %s certificate %s updated at %s',
    #                           key_type.upper(), certificate_name, last_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
    #             else:
    #                 last_update = None
    #
    #             ocsp_urls = (asn1crypto_certificate.ocsp_urls or cert_spec.ocsp_responder_urls)
    #             if ocsp_urls:
    #                 chain = self.load_chain(certificate_name, key_type)
    #                 issuer_certificate = chain[0] if chain else root_certificates[key_type]
    #                 issuer_asn1_certificate = asn1_x509.Certificate.load(certificate_bytes(issuer_certificate))
    #
    #                 tbs_request = asn1_ocsp.TBSRequest({
    #                     'request_list': [
    #                         {
    #                             'req_cert': {
    #                                 'hash_algorithm': {'algorithm': 'sha1'},
    #                                 'issuer_name_hash': asn1crypto_certificate.issuer.sha1,
    #                                 'issuer_key_hash': issuer_asn1_certificate.public_key.sha1,
    #                                 'serial_number': asn1crypto_certificate.serial_number,
    #                             },
    #                             'single_request_extensions': None
    #                         }
    #                     ],
    #                     'request_extensions': None  # [{'extn_id': 'nonce', 'critical': False, 'extn_value': os.urandom(16)}]
    #                     # we don't appear to be getting the nonce back, so don't send it
    #                 })
    #                 ocsp_request = asn1_ocsp.OCSPRequest({
    #                     'tbs_request': tbs_request,
    #                     'optional_signature': None
    #                 })
    #
    #                 for ocsp_url in ocsp_urls:
    #                     ocsp_response = fetch_ocsp_response(ocsp_url, ocsp_request, last_update)
    #                     if ocsp_response:
    #                         if 'successful' == ocsp_response['response_status'].native:
    #                             ocsp_status = ocsp_response_status(ocsp_response)
    #                             this_update = ocsp_response_this_update(ocsp_response)
    #                             log.debug('Retrieved OCSP status "%s" for %s certificate %s from %s updated at %s', ocsp_status.upper(),
    #                                       key_type.upper(), certificate_name, ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
    #                             if 'good' == ocsp_status.lower():
    #                                 if this_update == last_update:
    #                                     log.debug('OCSP response for %s certificate %s from %s has not been updated',
    #                                               key_type.upper(), certificate_name, ocsp_url)
    #                                     break
    #                                 log.info('Saving OCSP response for %s certificate %s from %s', key_type.upper(), certificate_name, ocsp_url)
    #                                 transactions.append(self.save_ocsp_response(certificate_name, key_type, ocsp_response))
    #                                 self._add_hook('ocsp_installed', certificate_name=certificate_name, key_type=key_type,
    #                                                ocsp_file=self.fs.filepath('ocsp', certificate_name, key_type))
    #                                 break
    #                             else:
    #                                 log.warning('%s certificate %s has OCSP status "%s" from %s updated at %s', key_type.upper(), certificate_name,
    #                                             ocsp_status.upper(), ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
    #                         else:
    #                             log.warning('%s certificate %s: OCSP request received "%s" from %s', key_type.upper(), certificate_name,
    #                                         ocsp_response['response_status'].native, ocsp_url)
    #                     elif ocsp_response is False:
    #                         log.debug('OCSP response for %s certificate %s from %s has not been updated', key_type.upper(), certificate_name, ocsp_url)
    #                         break
    #                 else:
    #                     log.warning('Unable to retrieve OCSP response for %s certificate %s', key_type.upper(), certificate_name)
    #             else:
    #                 log.warning('No OCSP responder URL for %s certificate %s and no default set', key_type.upper(), certificate_name)
    #
    #         if transactions:
    #             try:
    #                 self._commit_file_transactions(transactions, archive_name=None)
    #                 self._call_hooks()
    #                 self.update_services(cert_spec.services)
    #                 self.update_certificate(certificate_name)
    #             except Exception as error:
    #                 log.warning('Unable to save OCSP responses for %s: %s', certificate_name, str(error))
    #                 self._clear_hooks()

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
                action.run(cert)

            action.finalize()

            # if (not (
            #         self.args.revoke or self.args.auth or self.args.certs or self.args.sct or self.args.ocsp or self.args.symlink or self.args.verify or self.args.export_key_path)):
            #     self.args.auth = True
            #     self.args.certs = True
            #     self.args.sct = True
            #     self.args.ocsp = True
            #     self.args.symlink = True
            #     self.args.verify = True
            #
            # if self.args.export_key_path:
            #     self.export_client_key(self.args.export_key_path)
            #
            # contexts = []  # type: List[CertificateContext]
            # for cert_name in self.args.certificate_names or self.config.certificates.keys():
            #     spec = self.config.certificates.get(cert_name)
            #     if not spec:
            #         log.warning("requested certificate '%s' does not exists in config", cert_name)
            #     contexts.append(CertificateContext(cert_name, spec, self.fs))
            #
            # done = []  # type: List[CertificateContext]
            # for context in contexts:
            #     try:
            #         if self.args.auth and not self.config.get('mode') == 'follower':
            #             self.process_authorizations(context)
            #         # In maste mode, no need to perform any other task
            #         if self.config.get('mode') == 'master':
            #             continue
            #
            #         if self.args.certs:
            #             self.process_certificates(context)
            #         if self.args.sct:
            #             self.update_signed_certificate_timestamps(context)
            #         if self.args.ocsp:
            #             self.update_ocsp_responses(context)
            #
            #         if context.updated:
            #             context.commit()
            #
            #         if self.args.symlink:
            #             self.process_symlinks(context)
            #         # Save context processed without error
            #         done.append(context)
            #     except AcmeError as e:
            #         log.error("[%s] processing failed. No files updated\n%s", context.name, str(e))
            #
            # self.disconnect_client()


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
