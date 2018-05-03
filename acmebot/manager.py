import argparse
import base64
import datetime
import getpass
import heapq
import json
import logging
import os
import random
import re
import shlex
import socket
import struct
import subprocess
import sys
import time
import urllib
from logging import FileHandler, StreamHandler
from typing import Dict
from typing import List, Optional

import OpenSSL
import collections
import josepy
import pkg_resources
from OpenSSL.crypto import X509, PKey
from acme import client, messages
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from acmebot.config import CertificateSpec
from . import PrivateKeyError, log, AcmeError
from .config import Configuration
from .crypto import save_chain, check_dhparam, check_ecparam, certificate_bytes, save_certificate, private_key_matches_options, private_key_descripton, \
    generate_private_key, get_alt_names, private_key_matches_certificate, has_oscp_must_staple, \
    datetime_from_asn1_generaltime, generate_csr, decode_full_chain, get_dhparam_size, generate_dhparam, get_ecparam_curve, generate_ecparam, \
    certificates_match, private_key_export
from .ocsp import load_ocsp_response, ocsp_response_status, ocsp_response_serial_number, ocsp_response_this_update, fetch_ocsp_response
from .utils import FileTransaction, makedir, open_file, ColorFormatter, rename_file, host_in_list, fetch_tls_info, process_running

ChallengeTuple = collections.namedtuple('ChallengeTuple', ['identifier', 'response'])
AuthorizationTuple = collections.namedtuple('AuthorizationTuple', ['datetime', 'domain_name', 'authorization_resource'])

SCTData = collections.namedtuple('SCTData', ['version', 'id', 'timestamp', 'extensions', 'signature'])

KeyCipherData = collections.namedtuple('KeyCipherData', ['cipher', 'passphrase', 'forced'])


class CertParams(object):
    __slots__ = ('dhparams', 'ecparams')

    def __init__(self, dhparams: Optional[str], ecparams: Optional[str]):
        self.dhparams = dhparams
        self.ecparams = ecparams


class CertificateItem(object):
    __slots__ = ('updated', 'key', 'chain', 'certificate')

    def __init__(self):
        self.updated = False

        self.key = None  # type: PKey
        self.chain = None
        self.certificate = None  # type: X509


class CertificateData(object):
    __slots__ = ('name', 'spec', 'params', 'params_updated', 'certificates')

    def __init__(self, name: str, spec: CertificateSpec):
        self.name = name
        self.spec = spec

        self.params = CertParams(None, None)
        self.params_updated = False
        self.certificates = {key_type: CertificateItem() for key_type in spec.key_types}  # type: Dict[str, CertificateItem]


class AcmeManager(object):

    def __init__(self, script_dir, script_name):
        self.script_dir = script_dir
        self.script_name = script_name
        self.script_version = '3.0.0'

        argparser = argparse.ArgumentParser(description='ACME Certificate Manager')
        argparser.add_argument('--version', action='version', version='%(prog)s ' + self.script_version)
        argparser.add_argument('private_key_names', nargs='*')
        argparser.add_argument('-q', '--quiet',
                               action='store_true', dest='quiet', default=False,
                               help="Don't print status messages to stdout or warnings to stderr")
        argparser.add_argument('-v', '--verbose',
                               action='store_true', dest='verbose', default=False,
                               help='Print more detailed status messages to stdout')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='Print detailed debugging information to stdout')
        argparser.add_argument('-D', '--detail',
                               action='store_true', dest='detail', default=False,
                               help='Print more detailed debugging information to stdout')
        argparser.add_argument('--color',
                               action='store_true', dest='color', default=True,
                               help='Colorize output')
        argparser.add_argument('--no-color',
                               action='store_true', dest='no_color', default=False,
                               help='Suppress colorized output')
        argparser.add_argument('-c', '--config',
                               dest='config_path', default=self.script_name + '.json', metavar='CONFIG_PATH',
                               help='Specify file path for config')
        argparser.add_argument('-w', '--randomwait',
                               action='store_true', dest='random_wait', default=False,
                               help='Wait for a random time before executing')
        argparser.add_argument('-r', '--rollover',
                               action='store_true', dest='rollover', default=False,
                               help='Rollover Diffie-Hellman parameters')
        argparser.add_argument('-R', '--renew',
                               action='store_true', dest='renew', default=False,
                               help='Renew certificate regardless of age')
        argparser.add_argument('-K', '--revoke',
                               action='store_true', dest='revoke', default=False,
                               help='Revoke certificate')
        argparser.add_argument('-a', '--auth',
                               action='store_true', dest='auth', default=False,
                               help='Update authorizations only')
        argparser.add_argument('-C', '--certs',
                               action='store_true', dest='certs', default=False,
                               help='Update certificates only')
        argparser.add_argument('-s', '--sct',
                               action='store_true', dest='sct', default=False,
                               help='Update Signed Certificate Timestamps only')
        argparser.add_argument('-o', '--ocsp',
                               action='store_true', dest='ocsp', default=False,
                               help='Update OCSP responses only')
        argparser.add_argument('-S', '--symlink',
                               action='store_true', dest='symlink', default=False,
                               help='Create symlinks to simplify certificate management')
        argparser.add_argument('-V', '--verify',
                               action='store_true', dest='verify', default=False,
                               help='Verify certificate installation only')
        argparser.add_argument('--export-client',
                               action='store_true', dest='export_client', default=False,
                               help='Export client key')
        argparser.add_argument('-p', '--pass', nargs=1, default=False,
                               action='store', dest='passphrase', metavar='PASSPHRASE',
                               help='Passphrase for private keys')
        self.args = argparser.parse_args()

        if self.args.debug:
            sys.excepthook = debug_hook

        self.acme_client = None
        self.key_passphrases = {}
        self.updated_services = set()
        self.updated_certificates = set()
        self.hooks = collections.OrderedDict()

        # reset root logger
        for handler in list(log.handlers):
            log.removeHandler(handler)
        # create console handler
        stream = StreamHandler(sys.stderr)
        # enable color output
        if sys.stderr.isatty() and self.args.color and not self.args.no_color:
            stream.setFormatter(ColorFormatter())
        log.addHandler(stream)

        if self.args.detail or self.args.debug:
            log.setLevel(logging.DEBUG)
        elif self.args.verbose:
            log.setLevel(logging.INFO)
        else:
            log.setLevel(logging.WARNING)

        self.config = Configuration.load(self.args.config_path, ('.', os.path.join('/etc', self.script_name), self.script_dir))
        if not self.config.get('color_output'):
            # Reset formatter in case we don't want color
            stream.setFormatter(logging.Formatter())

        level = self.config.get('log_level')
        if level is not None:
            levels = {
                "normal": logging.WARNING,
                "verbose": logging.INFO,
                "debug": logging.DEBUG,
                "detail": logging.DEBUG,
            }
            if level not in levels:
                log.warning("[config] unsupported log level: %s", level)
                level = "normal"
                log.setLevel(levels[level])
            # if level is None, don't create log file
            if self.config.directory('log') and self.config.filename('log'):
                makedir(self.config.directory('log'), 0o700)
                log_file_path = self.config.filepath('log', self.script_name)
                log.addHandler(FileHandler(log_file_path, encoding='UTF-8'))

    def _archive_file(self, file_type, file_path, archive_name='', archive_date=datetime.datetime.now()):
        if os.path.isfile(file_path) and (not os.path.islink(file_path)) and (archive_name is not None):
            archive_file_path = os.path.join(self.config.directory('archive'),
                                             archive_name,
                                             archive_date.strftime('%Y_%m_%d_%H%M%S') if archive_date else '',
                                             file_type + '.' + os.path.basename(file_path))
            makedir(os.path.dirname(archive_file_path), 0o640)
            os.rename(file_path, archive_file_path)
            log.debug('Archived "%s" as "%s"', file_path, archive_file_path)
            return file_path, archive_file_path
        return None, None

    def _rename_file(self, old_file_path, new_file_path, chmod=None, timestamp=None):
        return rename_file(old_file_path, new_file_path, chmod, self.config.get('file_user'), self.config.get('file_group'), timestamp)

    def _commit_file_transactions(self, file_transactions, archive_name: Optional[str] = ''):
        archived_files = []
        committed_files = []
        try:
            if archive_name is not None:
                archive_date = datetime.datetime.now()
                for file_transaction in file_transactions:
                    archived_files.append(self._archive_file(file_transaction.file_type, file_transaction.file_path,
                                                             archive_name=archive_name, archive_date=archive_date))
            for file_transaction in file_transactions:
                committed_files.append(self._rename_file(file_transaction.temp_file_path, file_transaction.file_path,
                                                         chmod=file_transaction.chmod, timestamp=file_transaction.timestamp))
        except Exception as error:  # restore any archived files
            for committed_file_path in committed_files:
                if committed_file_path:
                    os.remove(committed_file_path)
            for original_file_path, archived_file_path in archived_files:
                if original_file_path:
                    os.rename(archived_file_path, original_file_path)
            raise error

    def update_certificate(self, certificate_name: str):
        self.updated_certificates.add(certificate_name)

    def update_services(self, services):
        if services:
            self.updated_services.update(services)

    def reload_services(self):
        reloaded = False
        for service_name in self.updated_services:
            service_command = self.config.service(service_name)
            if service_command:
                log.info('Reloading service %s', service_name)
                try:
                    output = subprocess.check_output(service_command, shell=True, stderr=subprocess.STDOUT)
                    reloaded = True
                    if output:
                        log.warning('Service "%s" responded to reload with:\n%s', service_name, output)
                except subprocess.CalledProcessError as error:
                    log.warning('Service "%s" reload failed, code: %s:\n%s', service_name, error.returncode, error.output)
            else:
                log.warning('Service %s does not have registered reload command', service_name)
        return reloaded

    def key_cipher_data(self, cert_name: str, force_prompt=False):
        if cert_name in self.key_passphrases:
            if self.key_passphrases[cert_name] or (not force_prompt):
                return self.key_passphrases[cert_name]
        cert_spec = self.config.certificates.get(cert_name)
        if cert_spec:
            passphrase = cert_spec.private_key.passphrase
            if (passphrase is True) or (force_prompt and not passphrase):
                if self.args.passphrase:
                    passphrase = self.args.passphrase[0]
                else:
                    passphrase = os.getenv('{script}_PASSPHRASE'.format(script=self.script_name.upper()))
                    if not passphrase:
                        if sys.stdin.isatty():
                            passphrase = getpass.getpass('Enter private key password for {name}: '.format(name=cert_name))
                        else:
                            passphrase = sys.stdin.readline().strip()
            key_cipher_data = KeyCipherData(cert_spec.private_key.cipher, passphrase, force_prompt) if passphrase else None
            self.key_passphrases[cert_name] = key_cipher_data
            return key_cipher_data
        return None

    def load_private_key(self, file_type: str, file_name: str, key_type: str, key_cipher_data=None):
        key_file_path = self.config.filepath(file_type, file_name, key_type)
        if os.path.isfile(key_file_path):
            try:
                with open(key_file_path, 'r') as private_key_file:
                    key_pem = private_key_file.read()
                    if '-----BEGIN ENCRYPTED PRIVATE KEY-----' in key_pem:
                        if not key_cipher_data:
                            key_cipher_data = self.key_cipher_data(file_name, force_prompt=True)
                        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem.encode('ascii'),
                                                                     key_cipher_data.passphrase.encode('utf-8'))
                    else:
                        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem.encode('ascii'))
                    return private_key
            except Exception as e:
                raise AcmeError("private key '{}' loading failed", key_file_path) from e
        return None

    def save_private_key(self, file_type, file_name, key_type, private_key, key_cipher_data,
                         timestamp=None, certificate=None, chain=None, dhparam_pem=None, ecparam_pem=None):
        with FileTransaction(file_type, self.config.filepath(file_type, file_name, key_type), chmod=0o640, timestamp=timestamp) as transaction:
            if private_key:
                if key_cipher_data and not key_cipher_data.forced:
                    try:
                        key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key, key_cipher_data.cipher,
                                                                 key_cipher_data.passphrase.encode('utf-8'))
                    except Exception as e:
                        raise PrivateKeyError(file_name) from e
                else:
                    key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
                transaction.write(key_pem.decode('ascii'))
                if certificate:
                    transaction.write('\n')
                    save_certificate(transaction, certificate, chain=chain, dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
        return transaction

    def archive_private_key(self, file_type, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file(file_type, self.config.filepath(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def load_certificate(self, file_type, file_name, key_type):
        cert_path = self.config.filepath(file_type, file_name, key_type)
        try:
            with open(cert_path, 'r') as certificate_file:
                return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_file.read().encode('ascii'))
        except FileNotFoundError:
            return None
        except Exception as e:
            raise AcmeError("Certificate loading failed ({})", cert_path) from e

    def load_root_certificates(self):
        root_certificates = collections.OrderedDict()
        # FIXME: factorize supported certificate types
        for key_type in ('rsa', 'ecdsa'):
            root_certificates[key_type] = self.load_certificate('certificate', os.path.join(os.path.dirname(self.config.path), 'root_cert'), key_type)
        return root_certificates

    def save_certificate(self, file_type, file_name, key_type, certificate, chain=None, root_certificate=None, dhparam_pem=None, ecparam_pem=None):
        with FileTransaction(file_type, self.config.filepath(file_type, file_name, key_type), chmod=0o644) as transaction:
            save_certificate(transaction.file, certificate, chain=chain, root_certificate=root_certificate, dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem)
        return transaction

    def archive_certificate(self, file_type, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file(file_type, self.config.filepath(file_type, file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def load_chain(self, file_name, key_type):
        chain = []
        try:
            pem_data = None
            if self.config.directory('chain'):
                chain_file_path = self.config.filepath('chain', file_name, key_type)
                if os.path.isfile(chain_file_path):
                    with open(chain_file_path) as chain_file:
                        pem_data = chain_file.read()
                        index = 0
            if not pem_data:
                with open(self.config.filepath('certificate', file_name, key_type)) as certificate_file:
                    pem_data = certificate_file.read()
                    index = 1
            certificate_pems = re.findall('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem_data, re.DOTALL)[index:]
            for certificate_pem in certificate_pems:
                chain.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_pem.encode('ascii')))
        except Exception as e:
            log.warning("error loading chain: %s", str(e))
        return chain

    def save_chain(self, file_name, key_type, chain):
        with FileTransaction('chain', self.config.filepath('chain', file_name, key_type), chmod=0o644) as transaction:
            save_chain(transaction.file, chain)
        return transaction

    def archive_chain(self, file_name, key_type, archive_name='', archive_date=None):
        self._archive_file('chain', self.config.filepath('chain', file_name, key_type), archive_name=archive_name, archive_date=archive_date)

    def params_present(self, file_name, dhparam_pem, ecparam_pem):
        param_file_path = self.config.filepath('param', file_name)
        if os.path.isfile(param_file_path):
            with open(param_file_path, 'r') as param_file:
                params = param_file.read()
                return ((not dhparam_pem) or (dhparam_pem in params)) and ((not ecparam_pem) or (ecparam_pem in params))
        return False

    def load_params(self, file_name) -> CertParams:
        try:
            pem_data = None
            if self.config.directory('param'):
                param_file_path = self.config.filepath('param', file_name)
                if os.path.isfile(param_file_path):
                    with open(param_file_path) as param_file:
                        pem_data = param_file.read()
            if not pem_data:
                for key_type in ('rsa', 'ecdsa'):
                    certificate_file_path = self.config.filepath('certificate', file_name, key_type)
                    if os.path.isfile(certificate_file_path):
                        with open(certificate_file_path) as certificate_file:
                            pem_data = certificate_file.read()
                        break
            if pem_data:
                match = re.match(r'.*(-----BEGIN DH PARAMETERS-----.*-----END DH PARAMETERS-----)', pem_data, re.DOTALL)
                dhparam_pem = (match.group(1) + '\n') if match else None
                match = re.match(r'.*(-----BEGIN EC PARAMETERS-----.*-----END EC PARAMETERS-----)', pem_data, re.DOTALL)
                ecparam_pem = (match.group(1) + '\n') if match else None
                if not check_dhparam(dhparam_pem):
                    dhparam_pem = None
                if not check_ecparam(ecparam_pem):
                    ecparam_pem = None
                return CertParams(dhparam_pem, ecparam_pem)
        except Exception as e:
            log.error("param loading error: %s", str(e))
        return CertParams(None, None)

    def save_params(self, file_name, dhparam_pem, ecparam_pem):
        with FileTransaction('param', self.config.filepath('param', file_name), chmod=0o640) as transaction:
            if dhparam_pem and ecparam_pem:
                transaction.write(dhparam_pem + '\n' + ecparam_pem)
            else:
                transaction.write(dhparam_pem or ecparam_pem)
        return transaction

    def archive_params(self, file_name, archive_name='', archive_date=None):
        self._archive_file('param', self.config.filepath('param', file_name), archive_name=archive_name, archive_date=archive_date)

    @staticmethod
    def _sct_datetime(sct_timestamp):
        return datetime.datetime.utcfromtimestamp(sct_timestamp / 1000)

    def fetch_sct(self, ct_log_name, certificate, chain):
        ct_log = self.config.ct_log(ct_log_name)
        if ct_log and ('url' in ct_log):
            certificates = ([base64.b64encode(certificate_bytes(certificate)).decode('ascii')]
                            + [base64.b64encode(certificate_bytes(chain_certificate)).decode('ascii') for chain_certificate in chain])
            request_data = json.dumps({'chain': certificates}).encode('ascii')
            request = urllib.request.Request(url=ct_log['url'] + '/ct/v1/add-chain', data=request_data)
            request.add_header('Content-Type', 'application/json')
            try:
                with urllib.request.urlopen(request) as response:
                    sct = json.loads(response.read().decode('utf-8'))
                    return SCTData(sct.get('sct_version'), sct.get('id'), sct.get('timestamp'), sct.get('extensions'), sct.get('signature'))
            except urllib.error.HTTPError as error:
                if (400 <= error.code) and (error.code < 500):
                    log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)\n%s', ct_log_name, error.code, error.reason, error.read())
                else:
                    log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)', ct_log_name, error.code, error.reason)
            except urllib.error.URLError as error:
                log.warning('Unable to retrieve SCT from log %s: %s', ct_log_name, error.reason)
            except Exception as error:
                log.warning('Unable to retrieve SCT from log %s: %s', ct_log_name, str(error))
        else:
            log.warning('Unknown CT log: %s', ct_log_name)
        return None

    def load_sct(self, file_name, key_type, ct_log_name):
        try:
            ct_log = self.config.ct_log(ct_log_name)
            if ct_log and ('id' in ct_log):
                sct_file_path = self.config.filepath('sct', file_name, key_type, ct_log_name=ct_log_name)
                with open(sct_file_path, 'rb') as sct_file:
                    sct = sct_file.read()
                    version, logid, timestamp, extensions_len = struct.unpack('>b32sQH', sct[:43])
                    logid = base64.b64encode(logid).decode('ascii')
                    extensions = base64.b64encode(sct[43:(43 + extensions_len)]).decode('ascii') if extensions_len else ''
                    signature = base64.b64encode(sct[43 + extensions_len:]).decode('ascii')

                    if ct_log['id'] == logid:
                        return SCTData(version, logid, timestamp, extensions, signature)
                    else:
                        log.debug('SCT "%s" does not match log id for "%s"', sct_file_path, ct_log_name)
        except Exception as e:
            log.warning("error loading sct log: %s", str(e))
        return None

    def save_sct(self, file_name, key_type, ct_log_name, sct_data):
        ct_log = self.config.ct_log(ct_log_name)
        if ct_log:
            with FileTransaction('sct', self.config.filepath('sct', file_name, key_type, ct_log_name=ct_log_name), chmod=0o640, mode='wb') as transaction:
                extensions = base64.b64decode(sct_data.extensions)
                sct = struct.pack('>b32sQH', sct_data.version, base64.b64decode(sct_data.id), sct_data.timestamp, len(extensions))
                sct += extensions + base64.b64decode(sct_data.signature)
                transaction.write(sct)
            return transaction
        return None

    def archive_sct(self, file_name, key_type, ct_log_name, archive_name='', archive_date=None):
        self._archive_file('sct', self.config.filepath('sct', file_name, key_type, ct_log_name=ct_log_name), archive_name=archive_name,
                           archive_date=archive_date)

    def load_oscp_response(self, file_name, key_type):
        return load_ocsp_response(self.config.filepath('ocsp', file_name, key_type))

    def save_ocsp_response(self, file_name, key_type, ocsp_response):
        with FileTransaction('ocsp', self.config.filepath('ocsp', file_name, key_type), chmod=0o640, mode='wb') as transaction:
            transaction.write(ocsp_response.dump())
        return transaction

    def _add_hook(self, hook_name: str, **kwargs):
        hooks = self.config.hook(hook_name)
        if hooks:
            if hook_name not in self.hooks:
                self.hooks[hook_name] = []

            # Hook take an array of commands, or a single command
            if isinstance(hooks, (str, dict)):
                hooks = (hooks,)
            try:
                for hook in hooks:
                    if isinstance(hook, str):
                        hook = {
                            'args': shlex.split(hook)
                        }
                    else:
                        hook = hook.copy()
                    hook['args'] = [arg.format(**kwargs) for arg in hook['args']]
                    self.hooks[hook_name].append(hook)
            except KeyError as error:
                log.warning('Invalid hook specification for %s, unknown key %s', hook_name, error)

    def _call_hooks(self):
        for hook_name, hooks in self.hooks.items():
            for hook in hooks:
                try:
                    log.debug('Calling hook %s: %s', hook_name, hook['args'])
                    # TODO: add support for cwd, env, …
                    log.info(subprocess.check_output(hook['args'], stderr=subprocess.STDOUT, shell=False))
                except subprocess.CalledProcessError as error:
                    log.warning('Hook %s returned error, code: %s:\n%s', hook_name, error.returncode, error.output)
                except Exception as e:
                    log.warning('Failed to call hook %s (%s): %s', hook_name, hook['args'], str(e))
        self._clear_hooks()

    def _clear_hooks(self):
        self.hooks.clear()

    def _user_agent(self):
        return '{script}/{version} acme-python/{acme_version}'.format(script=self.script_name, version=self.script_version,
                                                                      acme_version=pkg_resources.get_distribution('acme').version)

    def _generate_client_key(self):
        self.client_key = josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend()))

    def export_client_key(self):
        client_key_pem = private_key_export(self.client_key.key)
        client_key_file_path = 'acmebot_client_key.pem'
        try:
            with open(client_key_file_path, 'w') as client_key_file:
                client_key_file.write(client_key_pem.decode('ascii'))
                logging.info('Client key exported to %s', client_key_file_path)
        except Exception as error:
            logging.error('Unbale to write client key to %s: %s', client_key_file_path, str(error))

    def connect_client(self):
        resource_dir = os.path.join(self.script_dir, self.config.directory('resource'))
        makedir(resource_dir, 0o600)
        generated_client_key = False
        client_key_path = os.path.join(resource_dir, 'client_key.json')
        if os.path.isfile(client_key_path):
            with open(client_key_path) as client_key_file:
                self.client_key = josepy.JWKRSA.fields_from_json(json.load(client_key_file))
            log.debug('Loaded client key %s', client_key_path)
        else:
            log.info('Client key not present, generating')
            self._generate_client_key()
            generated_client_key = True

        registration = None
        registration_path = os.path.join(resource_dir, 'registration.json')
        if os.path.isfile(registration_path):
            with open(registration_path) as registration_file:
                registration = messages.RegistrationResource.json_loads(registration_file.read())
                log.debug('Loaded registration %s', registration_path)
                acme_url = urllib.parse.urlparse(self.config.get('acme_directory_url'))
                reg_url = urllib.parse.urlparse(registration.uri)
                if (acme_url[0] != reg_url[0]) or (acme_url[1] != reg_url[1]):
                    log.info('ACME service URL has changed, re-registering with new client key')
                    registration = None
                    # ACME-ISSUE Resetting the client key should not be necessary, but the new registration comes back empty if we use the old key
                    self._generate_client_key()
                    generated_client_key = True

        if registration:
            try:
                network = client.ClientNetwork(self.client_key, account=registration, user_agent=self._user_agent())
                self.acme_client = client.BackwardsCompatibleClientV2(network, self.client_key, self.config.get('acme_directory_url'))
            except Exception as error:
                log.error("Can't connect to ACME service: %s", str(error))
        else:
            log.debug('Registering client')
            try:
                network = client.ClientNetwork(self.client_key, user_agent=self._user_agent())
                self.acme_client = client.BackwardsCompatibleClientV2(network, self.client_key, self.config.get('acme_directory_url'))
            except Exception as error:
                log.error("Can't connect to ACME service: %s", str(error))

            def _accept_tos(tos):
                if sys.stdin.isatty():
                    sys.stdout.write('ACME service has the following terms of service:\n')
                    sys.stdout.write(tos)
                    sys.stdout.write('\n')
                    answer = input('Accept? (Y/n) ')
                    if answer and not answer.lower().startswith('y'):
                        raise Exception('Terms of service rejected.')
                    log.debug('Terms of service accepted.')
                else:
                    log.debug('Auto-accepting TOS: %s', tos)

            try:
                reg = messages.NewRegistration.from_data(email=self.config.account['email'])
                registration = self.acme_client.new_account_and_tos(reg, _accept_tos)
            except Exception as error:
                log.error("Can't register with ACME service: %s", str(error))

            transactions = []
            if generated_client_key:
                with FileTransaction('client', client_key_path, chmod=0o600) as client_key_transaction:
                    client_key_transaction.write(json.dumps(self.client_key.fields_to_partial_json()))
                    log.debug('Saved client key %s', client_key_path)
                    transactions.append(client_key_transaction)

            with FileTransaction('registration', registration_path, chmod=0o600) as registration_transaction:
                registration_transaction.write(registration.json_dumps())
                log.debug('Saved registration %s', registration_path)
                transactions.append(registration_transaction)
            try:
                self._commit_file_transactions(transactions, archive_name='client')
            except Exception as e:
                log.error('Unable to save registration to %s: %s', registration_path, str(e))

    def disconnect_client(self):
        if self.acme_client:
            del self.acme_client

    @staticmethod
    def _get_challenge(authorization_resource, ty):
        for challenge in authorization_resource.body.challenges:
            if ty == challenge.typ:
                return challenge
        return None

    def _handle_authorizations(self, order, fetch_only, domain_names: List[str]):
        authorization_resources = {}

        for authorization_resource in order.authorizations:
            domain_name = authorization_resource.body.identifier.value
            if messages.STATUS_VALID == authorization_resource.body.status:
                log.debug('%s already authorized', domain_name)
            elif messages.STATUS_PENDING == authorization_resource.body.status:
                if not fetch_only:
                    authorization_resources[domain_name] = authorization_resource
                    log.debug('Requesting authorization for %s', domain_name)
                else:
                    log.debug('%s not authorized', domain_name)
            else:
                log.error('Unexpected status "%s" for authorization of %s', authorization_resource.body.status, domain_name)

        # set challenge responses
        challenge_types = {}
        challenge_http_responses = {}
        for domain_name in domain_names:
            if domain_name in authorization_resources:
                authorization_resource = authorization_resources[domain_name]
                identifier = authorization_resource.body.identifier.value
                http_challenge_directory = self.config.http_challenge_directory(identifier)
                if not http_challenge_directory:
                    log.warning("no http_challenge_directory directory specified for domain %s", domain_name)
                    continue
                challenge_types[domain_name] = 'http-01'
                challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
                if not challenge:
                    log.warning('Unable to use http-01 challenge for %s', domain_name)
                    continue
                challenge_file_path = os.path.join(http_challenge_directory, challenge.chall.encode('token'))
                log.debug('Setting http acme-challenge for "%s" in file "%s"', domain_name, challenge_file_path)
                try:
                    with open_file(challenge_file_path, 'w', 0o644) as challenge_file:
                        challenge_file.write(challenge.validation(self.client_key))
                    challenge_http_responses[domain_name] = challenge_file_path
                    self._add_hook('set_http_challenge', domain=domain_name, challenge_file=challenge_http_responses[domain_name])
                except Exception as error:
                    log.warning('Unable to create acme-challenge file "%s": %s', challenge_file_path, str(error))
        self._call_hooks()

        # answer challenges
        for domain_name in authorization_resources:
            authorization_resource = authorization_resources[domain_name]
            log.debug('Answering challenge for %s', domain_name)
            challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
            try:
                self.acme_client.answer_challenge(challenge, challenge.response(self.client_key))
            except Exception as error:
                log.warning('Error answering challenge for %s: %s', domain_name, str(error))

        # poll for authorizations
        waiting = [AuthorizationTuple(datetime.datetime.now(), domain_name, authorization_resource)
                   for domain_name, authorization_resource in authorization_resources.items()]
        attempts = collections.defaultdict(int)
        exhausted = {}
        failed = {}
        while waiting:
            when, domain_name, authorization_resource = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if now < when:
                seconds = (when - now).seconds
                if 0 < seconds:
                    time.sleep(seconds)
                    log.debug('Polling for %s', domain_name)
            try:
                authorization_resource, response = self.acme_client.poll(authorization_resource)
                if 200 != response.status_code:
                    log.warning('%s while waiting for domain challenge for %s', response, domain_name)
                    heapq.heappush(waiting, AuthorizationTuple(
                        self.acme_client.retry_after(response, default=self.config.int('authorization_delay')),
                        domain_name, authorization_resource))
                    continue
            except Exception as error:
                log.warning('Error polling for authorization for %s: %s', domain_name, str(error))
                continue

            authorization_resources[domain_name] = authorization_resource
            attempts[authorization_resource] += 1
            if messages.STATUS_VALID == authorization_resource.body.status:
                log.debug('Authorization received')
                continue
            elif messages.STATUS_INVALID == authorization_resource.body.status:
                error = self._get_challenge(authorization_resource, challenge_types[domain_name]).error
                log.debug('Invalid authorization: %s', error.detail if error else 'Unknown error')
                failed[domain_name] = authorization_resource
            elif messages.STATUS_PENDING == authorization_resource.body.status:
                if self.config.int('max_authorization_attempts') < attempts[authorization_resource]:
                    exhausted[domain_name] = authorization_resource
                    log.debug('Giving up')
                else:
                    log.debug('Retrying')
                    heapq.heappush(waiting, AuthorizationTuple(
                        self.acme_client.retry_after(response, default=self.config.int('authorization_delay')),
                        domain_name, authorization_resource))
            else:
                log.error('Unexpected status "%s"', authorization_resource.body.status)

        for domain_name in challenge_http_responses:
            log.debug('Removing http acme-challenge for %s', domain_name)
            self._add_hook('clear_http_challenge', domain=domain_name, challenge_file=challenge_http_responses[domain_name])
            os.remove(challenge_http_responses[domain_name])
        self._call_hooks()

        for domain_name in failed:
            log.warning('Authorization failed for %s', domain_name)
        for domain_name in exhausted:
            log.warning('Authorization timed out for %s', domain_name)

        order.update(authorizations=[authorization_resource for authorization_resource in authorization_resources.values()])

    def _create_auth_order(self, domain_names: List[str]):
        if 1 == self.acme_client.acme_version:
            authorizations = []
            for domain_name in domain_names:
                try:
                    authorizations.append(self.acme_client.client.request_domain_challenges(domain_name))
                except Exception as error:
                    log.warning('Unable to request authorization for %s: %s', domain_name, str(error))
                    continue
            if authorizations:
                return messages.OrderResource(authorizations=authorizations)
        else:
            identifiers = []

            for domain_name in domain_names:
                identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain_name))

            if identifiers:
                order = messages.NewOrder(identifiers=identifiers)
                try:
                    response = self.acme_client.client._post(self.acme_client.client.directory['newOrder'], order)
                except Exception as error:
                    log.warning('Unable to create authorization order: %s', str(error))
                    return None
                body = messages.Order.from_json(response.json())
                authorizations = []
                for url in body.authorizations:
                    try:
                        authorizations.append(self.acme_client.client._authzr_from_response(self.acme_client.client.net.get(url), uri=url))
                    except Exception as error:
                        log.warning('Unable to request authorization for %s: %s', domain_name, str(error))
                        continue
                if authorizations:
                    return messages.OrderResource(body=body, uri=response.headers.get('Location'), authorizations=authorizations)
        return None

    def process_authorizations(self, cert_names=None):
        domain_names = []

        # gather domain names from all specified certtificates
        for certificate_name, cert_spec in self.config.certificates.items():
            if cert_names and (certificate_name not in cert_names):
                continue
            for domain_name in cert_spec.alt_names:
                if domain_name not in domain_names:
                    domain_names.append(domain_name)

        # gather domain names from authorizations
        for zone_name, hosts in self.config.authorizations.items():
            for domain_name in hosts:
                if domain_name not in domain_names:
                    domain_names.append(domain_name)

        authorization_groups = []
        for host_name in domain_names:
            for authorization_host_names in authorization_groups:
                if ((len(authorization_host_names) < self.config.int('max_domains_per_order'))
                        and not host_in_list(host_name, authorization_host_names)):
                    authorization_host_names.append(host_name)
                    break
            else:
                authorization_groups.append([host_name])

        for authorization_host_names in authorization_groups:
            order = self._create_auth_order(authorization_host_names)
            if order:
                self._handle_authorizations(order, False, domain_names)

    def _poll_order(self, order):
        response = self.acme_client.net.get(order.uri)
        body = messages.Order.from_json(response.json())
        if body.error is not None:
            raise body.error
        return order.update(body=body), response

    def _should_generate_certificate(self, name: str, key_type: str, spec: CertificateSpec, cert_item: CertificateItem):
        if not cert_item.certificate or not cert_item.key:
            return True

        params = spec.private_key.params(key_type)
        if not private_key_matches_options(key_type, cert_item.key, params):
            log.info('Private %s key is not %s', key_type.upper(), private_key_descripton(key_type, params))
            return True

        certificate_common_name = cert_item.certificate.get_subject().commonName
        if spec.common_name != certificate_common_name:
            log.info('Common name changed for %s certificate %s from %s to %s', key_type.upper(), name, certificate_common_name, spec.common_name)
            return True

        certificate_alt_names = get_alt_names(cert_item.certificate)
        new_alt_names = set(spec.alt_names)
        existing_alt_names = set(certificate_alt_names)
        if new_alt_names != existing_alt_names:
            added_alt_names = new_alt_names - existing_alt_names
            removed_alt_names = existing_alt_names - new_alt_names
            added = ', '.join([alt_name for alt_name in spec.alt_names if (alt_name in added_alt_names)])
            removed = ', '.join([alt_name for alt_name in certificate_alt_names if (alt_name in removed_alt_names)])
            log.info('Alt names changed for %s certificate %s%s%s', key_type.upper(), name,
                     (', adding ' + added) if added else '', (', removing ' + removed) if removed else '')
            return True

        if not private_key_matches_certificate(cert_item.key, cert_item.certificate):
            log.info('%s certificate %s public key does not match private key', key_type.upper(), name)
            return True

        cert_has_must_staple = has_oscp_must_staple(cert_item.certificate)
        if cert_has_must_staple != spec.ocsp_must_staple:
            log.info('%s certificate %s %s ocsp_must_staple option',
                     key_type.upper(), name, 'has' if cert_has_must_staple else 'does not have')
            return True

        valid_duration = (datetime_from_asn1_generaltime(cert_item.certificate.get_notAfter()) - datetime.datetime.utcnow())
        if valid_duration.days < 0:
            log.info('%s certificate %s has expired', key_type.upper(), name)
            return True
        if valid_duration.days < self.config.int('renewal_days'):
            log.info('%s certificate %s will expire in %s', key_type.upper(), name,
                     (str(valid_duration.days) + ' days') if valid_duration.days else 'less than a day')
            return True

        days_to_renew = valid_duration.days - self.config.int('renewal_days')
        log.debug('%s certificate %s valid beyond renewal window (renew in %s %s)', key_type.upper(), name,
                  days_to_renew, 'day' if (1 == days_to_renew) else 'days')
        return False

    def process_certificates(self, auth_fetch_only, cert_names=None):
        for certificate_name, cert_spec in self.config.certificates.items():
            if cert_names and (certificate_name not in cert_names):
                continue

            key_cipher_data = self.key_cipher_data(certificate_name)

            log.debug('Processing certificate %s', certificate_name)

            cert_data = CertificateData(certificate_name, cert_spec)

            # For each types, check if the cert exists and is valid (params match and not about to expire)
            for key_type in cert_spec.key_types:
                cert_item = cert_data.certificates[key_type]
                try:
                    cert_item.key = self.load_private_key('private_key', certificate_name, key_type, key_cipher_data)
                except PrivateKeyError as error:
                    log.warning('Unable to load private key %s: %s', certificate_name, str(error))
                    continue

                cert_item.certificate = self.load_certificate('certificate', certificate_name, key_type)
                if self._should_generate_certificate(certificate_name, key_type, cert_spec, cert_item):
                    log.info('Generating primary %s key for %s', key_type.upper(), certificate_name)
                    cert_item.key = generate_private_key(key_type, cert_spec.private_key.params(key_type))
                    if not cert_item.key:
                        raise AcmeError("{} private key generation failed for certificate {}", key_type.upper(), certificate_name)

                    csr_pem = generate_csr(cert_item.key, cert_spec.common_name, cert_spec.alt_names, cert_spec.ocsp_must_staple)
                    log.info('Requesting %s certificate for %s%s', key_type.upper(), cert_spec.common_name,
                             (' with alt names: ' + ', '.join(cert_spec.alt_names)) if cert_spec.alt_names else '')
                    try:
                        order = self.acme_client.new_order(csr_pem)
                        self._handle_authorizations(order, auth_fetch_only, cert_spec.alt_names)
                        if order.uri:
                            order, response = self._poll_order(order)
                            if messages.STATUS_INVALID == order.body.status:
                                log.warning('Unable to issue %s certificate %s', key_type.upper(), certificate_name)
                                continue
                        order = self.acme_client.finalize_order(order, datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('cert_poll_time')))
                        cert_item.certificate, cert_item.chain = decode_full_chain(order.fullchain_pem)
                    except Exception as error:
                        log.warning('%s certificate issuance failed: %s', key_type.upper(), str(error))
                        continue

                    log.debug('New %s certificate issued', key_type.upper())
                    cert_data.params = CertParams(None, None)
                    cert_item.updated = True
                elif not self.args.rollover:
                    # if we do not force refresh params
                    cert_data.params = self.load_params(certificate_name)

                # Updating dhparams
                dhparam_size = cert_spec.dhparam_size
                if cert_data.params.dhparams and dhparam_size and (dhparam_size != get_dhparam_size(cert_data.params.dhparams)):
                    log.info('Diffie-Hellman parameters for %s are not %s bits', certificate_name, dhparam_size)
                    cert_data.params.dhparams = None
                # Remove existing params
                if cert_data.params.dhparams and not dhparam_size:
                    cert_data.params.dhparams = None
                    cert_data.params_updated = True
                elif (not cert_data.params.dhparams) and dhparam_size:
                    log.info('Generating Diffie-Hellman parameters for %s', certificate_name)
                    cert_data.params.dhparams = generate_dhparam(dhparam_size)
                    if not cert_data.params.dhparams:
                        raise AcmeError('Diffie-Hellman parameters generation failed for {} bits', dhparam_size)
                    cert_data.params_updated = True

                # Updating ecparams
                ecparam_curve = cert_spec.ecparam_curve
                if cert_data.params.ecparams and ecparam_curve and (ecparam_curve != get_ecparam_curve(cert_data.params.ecparams)):
                    log.info('Elliptical curve parameters for %s are not curve %s', certificate_name, ecparam_curve)
                    cert_data.params.ecparams = None
                # Remove existing params
                if cert_data.params.ecparams and not ecparam_curve:
                    cert_data.params.ecparams = None
                    cert_data.params_updated = True
                elif (not cert_data.params.ecparams) and ecparam_curve:
                    log.info('Generating elliptical curve parameters for %s', certificate_name)
                    cert_data.params.ecparams = generate_ecparam(ecparam_curve)
                    if not cert_data.params.ecparams:
                        raise AcmeError('Elliptical curve parameters generation failed for curve {}', ecparam_curve)
                    cert_data.params_updated = True

            self.install_certificate(cert_data)

    def install_certificate(self, certificate: CertificateData):
        # install keys and certificates
        root_certificates = self.load_root_certificates()

        certificate_name = certificate.name
        cert_spec = certificate.spec

        transactions = []

        # dh and ec params
        dhparams = certificate.params.dhparams
        ecparams = certificate.params.ecparams

        if certificate.params_updated and self.config.directory('param'):
            if dhparams or ecparams:
                transactions.append(self.save_params(certificate_name, certificate.params.dhparams, certificate.params.ecparams))
                self._add_hook('params_installed', key_name=certificate_name, certificate_name=certificate_name,
                               params_file=self.config.filepath('param', certificate_name))
            else:
                # TODO: remove old params
                pass

        # save private keys
        key_cipher_data = self.key_cipher_data(certificate_name)
        for key_type, cert_item in certificate.certificates.items():
            if cert_item.updated or certificate.params_updated:
                transactions.append(self.save_certificate('certificate', certificate_name, key_type, cert_item.certificate,
                                                          chain=cert_item.chain, dhparam_pem=dhparams, ecparam_pem=ecparams))
                self._add_hook('certificate_installed', certificate_name=certificate_name, key_type=key_type,
                               certificate_file=self.config.filepath('certificate', certificate_name, key_type))

            if self.config.directory('full_certificate'):
                full_cert_file = self.config.filepath('full_certificate', certificate_name, key_type)
                exists = os.path.exists(full_cert_file)
                if root_certificates[key_type] and (not exists or cert_item.updated or certificate.params_updated):
                    transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, cert_item.certificate,
                                                              chain=cert_item.chain, root_certificate=root_certificates[key_type],
                                                              dhparam_pem=dhparams, ecparam_pem=ecparams))
                    self._add_hook('full_certificate_installed', certificate_name=certificate_name, key_type=key_type, full_certificate_file=full_cert_file)
                elif exists and not root_certificates[key_type]:
                    # TODO: remove existing full certificate
                    pass

            if self.config.directory('chain') and cert_item.updated:
                transactions.append(self.save_chain(certificate_name, key_type, cert_item.chain))
                self._add_hook('chain_installed', certificate_name=certificate_name, key_type=key_type,
                               chain_file=self.config.filepath('chain', certificate_name, key_type))

            if cert_item.updated:
                transactions.append(self.save_private_key('private_key', certificate_name, key_type, cert_item.key, key_cipher_data))
                self._add_hook('private_key_installed', certificate_name=certificate_name, key_type=key_type,
                               private_key_file=self.config.filepath('private_key', certificate_name, key_type),
                               passphrase=key_cipher_data.passphrase if key_cipher_data else None)

            if self.config.directory('full_key') and (cert_item.updated or certificate.params_updated):
                transactions.append(self.save_private_key('full_key', certificate_name, key_type, cert_item.key, key_cipher_data,
                                                          certificate=cert_item.certificate, chain=cert_item.chain,
                                                          dhparam_pem=dhparams, ecparam_pem=ecparams))
                self._add_hook('full_key_installed', certificate_name=certificate_name, key_type=key_type,
                               full_key_file=self.config.filepath('full_key', certificate_name, key_type))

        if transactions:
            try:
                self._commit_file_transactions(transactions, archive_name=certificate_name)
                self._call_hooks()

                updated = False
                for key_type, cert_item in certificate.certificates.items():
                    if cert_item.updated:
                        log.info('%s private keys and certificate for %s installed', key_type.upper(), certificate_name)
                        updated = True

                if updated:
                    self.update_services(cert_spec.services)
                    self.update_certificate(certificate_name)

            except Exception as error:
                log.warning('Unable to install keys and certificates for %s: %s', certificate_name, str(error))
                self._clear_hooks()

    def revoke_certificates(self, certificate_names):
        for certificate_name in certificate_names:
            cert_spec = self.config.certificates.get(certificate_name)
            if cert_spec:
                certificate_count = 0
                revoked_certificates = []
                for key_type in cert_spec.key_types:
                    certificate = self.load_certificate('certificate', certificate_name, key_type)
                    if certificate:
                        certificate_count += 1
                        try:
                            self.acme_client.revoke(josepy.ComparableX509(certificate), 0)
                            revoked_certificates.append(key_type)
                            log.info('%s certificate %s revoked', key_type.upper(), certificate_name)
                        except Exception as error:
                            log.warning('Unable to revoke %s certificate %s: %s', key_type.upper(), certificate_name, str(error))
                    else:
                        log.warning('%s certificate %s not found', key_type.upper(), certificate_name)

                archive_date = datetime.datetime.now()
                for key_type in revoked_certificates:
                    self.archive_certificate('certificate', certificate_name, key_type, archive_name=certificate_name, archive_date=archive_date)
                    self.archive_certificate('full_certificate', certificate_name, key_type, archive_name=certificate_name, archive_date=archive_date)
                    self.archive_chain(certificate_name, key_type, archive_name=certificate_name, archive_date=archive_date)
                    self.archive_private_key('full_key', certificate_name, key_type, archive_name=certificate_name, archive_date=archive_date)
                    self.archive_params(certificate_name, archive_name=certificate_name, archive_date=archive_date)
                    for ct_log_name in cert_spec.ct_submit_logs:
                        self.archive_sct(certificate_name, key_type, ct_log_name, archive_name=certificate_name, archive_date=archive_date)

                if len(revoked_certificates) == certificate_count:
                    for key_type in cert_spec.key_types:
                        self.archive_private_key('private_key', certificate_name, key_type, archive_name=certificate_name, archive_date=archive_date)
            else:
                log.warning('%s is not a configured private key', certificate_name)

    def update_signed_certificate_timestamps(self, certificates_names):
        if not self.config.directory('sct'):
            return

        for certificate_name, cert_spec in self.config.certificates.items():
            if certificates_names and (certificate_name not in certificates_names):
                continue

            if not cert_spec.ct_submit_logs:
                continue

            transactions = []
            for key_type in cert_spec.key_types:
                certificate = self.load_certificate('certificate', certificate_name, key_type)
                if not certificate:
                    log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
                    continue

                chain = self.load_chain(certificate_name, key_type)
                for ct_log_name in cert_spec.ct_submit_logs:
                    sct_data = self.fetch_sct(ct_log_name, certificate, chain)
                    if sct_data:
                        log.debug('%s has SCT for %s certificate %s at %s', ct_log_name, key_type.upper(),
                                  certificate_name, self._sct_datetime(sct_data.timestamp).isoformat())
                        existing_sct_data = self.load_sct(certificate_name, key_type, ct_log_name)
                        if sct_data and ((not existing_sct_data) or (sct_data != existing_sct_data)):
                            log.info('Saving Signed Certificate Timestamp for %s certificate %s from %s', key_type.upper(), certificate_name,
                                     ct_log_name)
                            transactions.append(self.save_sct(certificate_name, key_type, ct_log_name, sct_data))
                            self._add_hook('sct_installed', certificate_name=certificate_name, key_type=key_type, ct_log_name=ct_log_name,
                                           sct_file=self.config.filepath('sct', certificate_name, key_type, ct_log_name=ct_log_name))
            if transactions:
                try:
                    self._commit_file_transactions(transactions, archive_name=None)
                    self._call_hooks()

                    self.update_services(cert_spec.services)
                    self.update_certificate(certificate_name)
                except Exception as error:
                    log.warning('Unable to save Signed Certificate Timestamps for %s: %s', certificate_name, str(error))
                    self._clear_hooks()

    def update_ocsp_responses(self, certificate_names):
        if not self.config.directory('ocsp'):
            return

        root_certificates = self.load_root_certificates()

        for certificate_name, cert_spec in self.config.certificates.items():
            if certificate_names and (certificate_name not in certificate_names):
                continue

            # ignore ocsp if explicitly disabled for this certificate
            if not cert_spec.ocsp_responder_urls:
                continue

            transactions = []
            for key_type in cert_spec.key_types:
                certificate = self.load_certificate('certificate', certificate_name, key_type)
                if not certificate:
                    log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
                    continue

                asn1crypto_certificate = asn1_x509.Certificate.load(certificate_bytes(certificate))
                ocsp_response = self.load_oscp_response(certificate_name, key_type)
                if (ocsp_response and ('good' == ocsp_response_status(ocsp_response).lower())
                        and (ocsp_response_serial_number(ocsp_response) == asn1crypto_certificate.serial_number)):
                    last_update = ocsp_response_this_update(ocsp_response)
                    log.debug('Have stapled OCSP response for %s certificate %s updated at %s',
                              key_type.upper(), certificate_name, last_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                else:
                    last_update = None

                ocsp_urls = (asn1crypto_certificate.ocsp_urls or cert_spec.ocsp_responder_urls)
                if ocsp_urls:
                    chain = self.load_chain(certificate_name, key_type)
                    issuer_certificate = chain[0] if chain else root_certificates[key_type]
                    issuer_asn1_certificate = asn1_x509.Certificate.load(certificate_bytes(issuer_certificate))

                    tbs_request = asn1_ocsp.TBSRequest({
                        'request_list': [
                            {
                                'req_cert': {
                                    'hash_algorithm': {'algorithm': 'sha1'},
                                    'issuer_name_hash': asn1crypto_certificate.issuer.sha1,
                                    'issuer_key_hash': issuer_asn1_certificate.public_key.sha1,
                                    'serial_number': asn1crypto_certificate.serial_number,
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
                            if 'successful' == ocsp_response['response_status'].native:
                                ocsp_status = ocsp_response_status(ocsp_response)
                                this_update = ocsp_response_this_update(ocsp_response)
                                log.debug('Retrieved OCSP status "%s" for %s certificate %s from %s updated at %s', ocsp_status.upper(),
                                          key_type.upper(), certificate_name, ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                                if 'good' == ocsp_status.lower():
                                    if this_update == last_update:
                                        log.debug('OCSP response for %s certificate %s from %s has not been updated',
                                                  key_type.upper(), certificate_name, ocsp_url)
                                        break
                                    log.info('Saving OCSP response for %s certificate %s from %s', key_type.upper(), certificate_name, ocsp_url)
                                    transactions.append(self.save_ocsp_response(certificate_name, key_type, ocsp_response))
                                    self._add_hook('ocsp_installed', certificate_name=certificate_name, key_type=key_type,
                                                   ocsp_file=self.config.filepath('ocsp', certificate_name, key_type))
                                    break
                                else:
                                    log.warning('%s certificate %s has OCSP status "%s" from %s updated at %s', key_type.upper(), certificate_name,
                                                ocsp_status.upper(), ocsp_url, this_update.strftime('%Y-%m-%d %H:%M:%S UTC'))
                            else:
                                log.warning('%s certificate %s: OCSP request received "%s" from %s', key_type.upper(), certificate_name,
                                            ocsp_response['response_status'].native, ocsp_url)
                        elif ocsp_response is False:
                            log.debug('OCSP response for %s certificate %s from %s has not been updated', key_type.upper(), certificate_name, ocsp_url)
                            break
                    else:
                        log.warning('Unable to retrieve OCSP response for %s certificate %s', key_type.upper(), certificate_name)
                else:
                    log.warning('No OCSP responder URL for %s certificate %s and no default set', key_type.upper(), certificate_name)

            if transactions:
                try:
                    self._commit_file_transactions(transactions, archive_name=None)
                    self._call_hooks()
                    self.update_services(cert_spec.services)
                    self.update_certificate(certificate_name)
                except Exception as error:
                    log.warning('Unable to save OCSP responses for %s: %s', certificate_name, str(error))
                    self._clear_hooks()

    def _verify_certificate_installation(self, certificate_name, certificate, chain, key_type, host_name, port_number, starttls, cipher_list):
        ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ssl_context.set_cipher_list(cipher_list)

        try:
            if host_name.startswith('*.'):
                host_name = 'wildcard-test.' + host_name[2:]
            addr_info = socket.getaddrinfo(host_name, port_number, proto=socket.IPPROTO_TCP)
        except Exception as error:
            log.warning('ERROR: Unable to get address for %s: %s', host_name, str(error))
            return

        for addr in addr_info:
            host_desc = host_name + ' at ' + (('[' + addr[4][0] + ']') if (socket.AF_INET6 == addr[0]) else addr[4][0]) + ':' + str(port_number)
            try:
                log.debug('Connecting to %s with %s ciphers', host_desc, key_type.upper())
                installed_certificates, ocsp_staple = fetch_tls_info(addr, ssl_context, key_type, host_name, starttls)
                if has_oscp_must_staple(certificate):
                    attempts = 1
                    while (not ocsp_staple) and (attempts < self.config.int('max_ocsp_verify_attempts')):
                        time.sleep(self.config.int('ocsp_verify_retry_delay'))
                        log.debug('Retrying to fetch OCSP staple')
                        installed_certificates, ocsp_staple = fetch_tls_info(addr, ssl_context, key_type, host_name, starttls)
                        attempts += 1

                installed_certificate = installed_certificates[0]
                installed_chain = installed_certificates[1:]
                if certificates_match(certificate, installed_certificate):
                    log.info('%s certificate %s present on %s', key_type.upper(), certificate_name, host_desc, extra={'color': 'green'})
                else:
                    log.warning('ERROR: %s certificate "%s" mismatch on %s', key_type.upper(), installed_certificate.get_subject().commonName, host_desc)
                if len(chain) != len(installed_chain):
                    log.warning('ERROR: %s certificate chain length mismatch on %s, got %s intermediate(s), expected %s', key_type.upper(), host_desc,
                                len(installed_chain), len(chain))
                else:
                    for intermediate, installed_intermediate in zip(chain, installed_chain):
                        if certificates_match(intermediate, installed_intermediate):
                            log.info('Intermediate %s certificate "%s" present on %s', key_type.upper(), intermediate.get_subject().commonName, host_desc,
                                     extra={'color': 'green'})
                        else:
                            log.warning('ERROR: Intermediate %s certificate "%s" mismatch on %s', key_type.upper(),
                                        installed_intermediate.get_subject().commonName, host_desc)
                if ocsp_staple:
                    ocsp_status = ocsp_response_status(ocsp_staple)
                    if 'good' == ocsp_status.lower():
                        log.info('OCSP staple status is GOOD on %s', host_desc, extra={'color': 'green'})
                    else:
                        log.warning('ERROR: OCSP staple has status: %s on %s', ocsp_status.upper(), host_desc)
                else:
                    if has_oscp_must_staple(certificate):
                        log.warning('ERROR: Certificate has OCSP Must-Staple but no OSCP staple found on %s')

            except Exception as error:
                log.warning('ERROR: Unable to connect to %s via %s: %s', host_desc, key_type.upper(), str(error))

    def verify_certificate_installation(self, certificate_names):
        key_type_ciphers = {}
        ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ssl_sock = OpenSSL.SSL.Connection(ssl_context, socket.socket())
        all_ciphers = ssl_sock.get_cipher_list()
        key_type_ciphers['rsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'RSA' in cipher_name]).encode('ascii')
        key_type_ciphers['ecdsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'ECDSA' in cipher_name]).encode('ascii')

        for certificate_name, cert_spec in self.config.certificates.items():
            if certificate_names and (certificate_name not in certificate_names):
                continue

            verify_list = cert_spec.verify
            if not verify_list:
                continue

            keys = []
            key_cipher_data = self.key_cipher_data(certificate_name)
            try:
                for key_type in cert_spec.key_types:
                    keys.append((key_type, self.load_private_key('private_key', certificate_name, key_type, key_cipher_data)))
            except PrivateKeyError as error:
                log.warning('Unable to load private key %s: %s', certificate_name, str(error))
                continue

            for key_type in cert_spec.key_types:
                certificate = self.load_certificate('certificate', certificate_name, key_type)
                if not certificate:
                    log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
                    continue

                chain = self.load_chain(certificate_name, key_type)

                for verify in verify_list:
                    if verify.key_types and key_type not in verify.key_types:
                        continue
                    for host_name in verify.hosts or cert_spec.alt_names:
                        self._verify_certificate_installation(certificate_name, certificate, chain, key_type,
                                                              host_name, verify.port, verify.starttls, key_type_ciphers[key_type])

    def process_symlink(self, alt_names: List[str], target: str, link: str):
        create = os.path.exists(target)

        for alt_name in alt_names:
            src = os.path.join(self.config.directory('symlinks'), alt_name, link)
            if create:
                try:
                    if os.readlink(src) == target:
                        return
                except FileNotFoundError:
                    pass
                log.debug("create symlink '%s' pointing to '%s'", src, target)
                os.symlink(target, src)
            else:
                try:
                    os.remove(src)
                    log.debug("removing symlink '%s'", src)
                except FileNotFoundError:
                    pass

    def process_symlinks(self, certificate_names):
        if not self.config.directory('symlinks'):
            return

        for certificate_name, cert_spec in self.config.certificates.items():
            if certificate_names and (certificate_name not in certificate_names):
                continue

            log.debug('Update symlinks for %s', certificate_name)

            # Create target directories
            root = self.config.directory('symlinks')
            alt_names = cert_spec.alt_names
            for alt_name in alt_names:
                os.makedirs(os.path.join(root, alt_name), mode=0o755, exist_ok=True)

            target = self.config.filepath('param', certificate_name)
            self.process_symlink(alt_names, target, 'params.pem')

            for key_type in cert_spec.key_types:
                # Private Keys
                target = self.config.filepath('private_key', certificate_name, key_type)
                self.process_symlink(alt_names, target, key_type + '.key')

                target = self.config.filepath('full_key', certificate_name, key_type)
                self.process_symlink(alt_names, target, 'full.' + key_type + '.key')

                # Certificate
                target = self.config.filepath('certificate', certificate_name, key_type)
                self.process_symlink(alt_names, target, 'cert.' + key_type + '.pem')

                target = self.config.filepath('chain', certificate_name, key_type)
                self.process_symlink(alt_names, target, 'chain.' + key_type + '.pem')

                target = self.config.filepath('full_certificate', certificate_name, key_type)
                self.process_symlink(alt_names, target, 'cert+root.' + key_type + '.pem')

                # OCSP
                target = self.config.filepath('ocsp', certificate_name, key_type)
                self.process_symlink(alt_names, target, key_type + '.ocsp')

                for ct_log_name in cert_spec.ct_submit_logs:
                    target = self.config.filepath('sct', certificate_name, key_type, ct_log_name=ct_log_name)
                    self.process_symlink(alt_names, target, ct_log_name + '.' + key_type + '.sct')

    def run(self):
        log.info('\n----- %s executed at %s', self.script_name, str(datetime.datetime.now()))
        pid_file_path = os.path.join(self.config.directory('pid'), self.script_name + '.pid')
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
            if (not (
                    self.args.revoke or self.args.auth or self.args.certs or self.args.sct or self.args.ocsp or self.args.symlink or self.args.verify or self.args.export_client)):
                self.args.auth = True
                self.args.certs = True
                self.args.sct = True
                self.args.ocsp = True
                self.args.symlink = True
                self.args.verify = True

            if self.args.revoke or self.args.auth or self.args.certs or self.args.export_client:
                self.connect_client()

            if self.args.revoke:
                if not self.args.private_key_names:
                    log.error('Revocation must explicitly specify private key names')
                else:
                    self.revoke_certificates(self.args.private_key_names)
            if self.args.auth and not self.config.bool('follower_mode'):
                self.process_authorizations(self.args.private_key_names)
            if self.args.certs:
                self.process_certificates(self.config.bool('follower_mode'), self.args.private_key_names)
            if self.args.sct:
                self.update_signed_certificate_timestamps(self.args.private_key_names)
            if self.args.ocsp:
                self.update_ocsp_responses(self.args.private_key_names)
            if self.args.symlink:
                self.process_symlinks(self.args.private_key_names)
            if self.reload_services() and self.args.verify:
                time.sleep(5)  # allow time for services to reload before verification
            # Call hook usefull to sync status with other hosts
            if self.updated_certificates:
                self._add_hook('certificates_updated', certificates=json.dumps(sorted(self.updated_certificates)))
                self._call_hooks()
            if self.args.verify:
                self.verify_certificate_installation(self.args.private_key_names)
            if self.args.export_client:
                self.export_client_key()
            self.disconnect_client()
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