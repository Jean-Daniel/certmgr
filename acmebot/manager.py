import argparse
import base64
import datetime
import getpass
import hashlib
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
from typing import List, Iterable, Optional

import OpenSSL
import collections
import josepy
import pkg_resources
from acme import client, messages
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from . import PrivateKeyError, AcmeError, log
from .crypto import save_chain, check_dhparam, check_ecparam, certificate_bytes, save_certificate, public_key_bytes, certificate_public_key_bytes, \
    private_key_matches_options, private_key_descripton, generate_private_key, get_alt_names, private_key_matches_certificate, has_oscp_must_staple, \
    datetime_from_asn1_generaltime, generate_csr, decode_full_chain, get_dhparam_size, generate_dhparam, get_ecparam_curve, generate_ecparam, certificates_match
from .dns import TLSAData, lookup_tlsa_records, get_name_servers, lookup_dns_challenge, tlsa_data
from .config import Configuration, get_list
from .dns import get_primary_name_server, reload_zone, update_zone
from .ocsp import load_ocsp_response, ocsp_response_status, ocsp_response_serial_number, ocsp_response_this_update, fetch_ocsp_response
from .utils import FileTransaction, makedir, open_file, ColorFormatter, rename_file, host_in_list, fetch_tls_info, process_running

DNSTuple = collections.namedtuple('DNSTuple', ['datetime', 'name_server', 'domain_name', 'identifier', 'response', 'attempt_count'])
ChallengeTuple = collections.namedtuple('ChallengeTuple', ['identifier', 'response'])
AuthorizationTuple = collections.namedtuple('AuthorizationTuple', ['datetime', 'domain_name', 'authorization_resource'])

KeyData = collections.namedtuple('KeyData', ['key', 'timestamp'])
SCTData = collections.namedtuple('SCTData', ['version', 'id', 'timestamp', 'extensions', 'signature'])
PrivateKeyData = collections.namedtuple('PrivateKeyData', ['name', 'key_options', 'keys', 'backup_keys',
                                                           'generated_key', 'rolled_key', 'changed_key', 'issued_certificates'])
KeyCipherData = collections.namedtuple('KeyCipherData', ['cipher', 'passphrase', 'forced'])
CertificateData = collections.namedtuple('CertificateData', ['certificate_name', 'key_type', 'certificate', 'chain', 'config'])


class AcmeManager(object):

    def __init__(self, script_dir, script_name):
        self.script_dir = script_dir
        self.script_name = script_name
        self.script_version = '2.2.0'

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
                               action='store_true', dest='color', default=False,
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
                               help='Rollover private keys and Diffie-Hellman parameters')
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
        argparser.add_argument('-t', '--tlsa',
                               action='store_true', dest='tlsa', default=False,
                               help='Update TLSA records only')
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

        if self.args.detail or self.args.verbose:
            log.setLevel(logging.DEBUG)
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

    def _reload_zone(self, zone_name, critical=True):
        return reload_zone(self.config.get('reload_zone_command'), zone_name, critical)

    def _update_zone(self, updates, zone_name, zone_key, operation):
        return update_zone(self.config.get('nsupdate_command'), updates, zone_name, zone_key, operation)

    def _set_dns_challenges(self, zone_name, zone_key, challenges):
        updates = ['update add _acme-challenge.{host} 300 TXT "{response}"'.format(host=challenges[domain_name].identifier,
                                                                                   response=challenges[domain_name].response)
                   for domain_name in challenges]
        return self._update_zone(updates, zone_name, zone_key, 'Set DNS challenges')

    def _remove_dns_challenges(self, zone_name, zone_key, challenges):
        updates = ['update delete _acme-challenge.{host} 300 TXT "{response}"'.format(host=challenges[domain_name].identifier,
                                                                                      response=challenges[domain_name].response)
                   for domain_name in challenges]
        self._update_zone(updates, zone_name, zone_key, 'Remove DNS challenges')

    def _set_tlsa_records(self, zone_name, zone_key, tlsa_records: Iterable[TLSAData]):
        usage = {'pkix-ta': '0', 'pkix-ee': '1', 'dane-ta': '2', 'dane-ee': '3'}
        updates = []
        name_server = get_primary_name_server(zone_name)
        if not name_server:
            return
        for tlsa_data in tlsa_records:
            host_name = zone_name if ('@' == tlsa_data.host) else (tlsa_data.host + '.' + zone_name)
            if tlsa_data.usage in usage:
                usage_id = usage[tlsa_data.usage]
            else:
                log.warning('Unknown TLSA usage %s', tlsa_data.usage)
                usage_id = usage['pkix-ee']
            if 'cert' == tlsa_data.selector:
                if tlsa_data.usage in ('pkix-ee', 'dane-ee'):
                    certificates = [certificate_bytes(certificate) for certificate in tlsa_data.certificates]
                else:
                    certificates = [certificate_bytes(certificate) for certificate in tlsa_data.chain]
                keys = []
            else:
                certificates = []
                if tlsa_data.usage in ('pkix-ee', 'dane-ee'):
                    keys = [public_key_bytes(private_key) for private_key in tlsa_data.private_keys]
                else:
                    keys = [certificate_public_key_bytes(certificate) for certificate in tlsa_data.chain]

            record_name = '_{port}._{protocol}.{host}.'.format(host=host_name, port=tlsa_data.port, protocol=tlsa_data.protocol)
            records = []
            record_bytes = set()
            for cert_bytes in certificates:
                if cert_bytes and cert_bytes not in record_bytes:  # dedupe chain certificates (may be shared between key types)
                    record_bytes.add(cert_bytes)
                    records.append('{usage} 0 1 {digest}'.format(usage=usage_id, digest=hashlib.sha256(cert_bytes).hexdigest()))
                    records.append('{usage} 0 2 {digest}'.format(usage=usage_id, digest=hashlib.sha512(cert_bytes).hexdigest()))
            for key_bytes in keys:
                if key_bytes and key_bytes not in record_bytes:  # dedupe chain certificates (may be shared between key types)
                    record_bytes.add(key_bytes)
                    records.append('{usage} 1 1 {digest}'.format(usage=usage_id, digest=hashlib.sha256(key_bytes).hexdigest()))
                    records.append('{usage} 1 2 {digest}'.format(usage=usage_id, digest=hashlib.sha512(key_bytes).hexdigest()))

            if set(records) == set(lookup_tlsa_records(name_server, host_name, tlsa_data.port, tlsa_data.protocol)):
                log.debug('TLSA records already present for %s', record_name)
                continue

            updates.append('update delete {record_name} {ttl} TLSA'.format(record_name=record_name, ttl=tlsa_data.ttl))
            for record in records:
                updates.append('update add {record_name} {ttl} TLSA {record}'.format(record_name=record_name, record=record, ttl=tlsa_data.ttl))
        if updates:
            self._update_zone(updates, zone_name, zone_key, 'Set TLSA')

    def _remove_tlsa_records(self, zone_name, zone_key, tlsa_records):
        updates = []
        for tlsa_data in tlsa_records:
            host_name = zone_name if ('@' == tlsa_data.host) else (tlsa_data.host + '.' + zone_name)
            updates.append('update delete _{port}._{proto}.{host}. TLSA'.format(port=tlsa_data.port, proto=tlsa_data.protocol, host=host_name))
        self._update_zone(updates, zone_name, zone_key, 'Remove TLSA')

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

    def key_cipher_data(self, private_key_name, force_prompt=False):
        if private_key_name in self.key_passphrases:
            if self.key_passphrases[private_key_name] or (not force_prompt):
                return self.key_passphrases[private_key_name]
        pk_spec = self.config.private_keys.get('private_key_name')
        if pk_spec:
            passphrase = pk_spec.key_passphrase
            if (passphrase is True) or (force_prompt and not passphrase):
                if self.args.passphrase:
                    passphrase = self.args.passphrase[0]
                else:
                    passphrase = os.getenv('{script}_PASSPHRASE'.format(script=self.script_name.upper()))
                    if not passphrase:
                        if sys.stdin.isatty():
                            passphrase = getpass.getpass('Enter private key password for {name}: '.format(name=private_key_name))
                        else:
                            passphrase = sys.stdin.readline().strip()
            key_cipher_data = KeyCipherData(pk_spec.key_cipher, passphrase, force_prompt) if passphrase else None
            self.key_passphrases[private_key_name] = key_cipher_data
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
                    return KeyData(private_key, os.stat(key_file_path).st_mtime)
            except Exception as e:
                raise PrivateKeyError(key_file_path) from e
        return KeyData(None, None)

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

    @staticmethod
    def _need_to_rollover(backup_key_age, expiration_days):
        if (backup_key_age is not None) and expiration_days:
            return expiration_days <= backup_key_age.days
        return False

    def load_certificate(self, file_type, file_name, key_type):
        cert_path = self.config.filepath(file_type, file_name, key_type)
        try:
            with open(cert_path, 'r') as certificate_file:
                return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_file.read().encode('ascii'))
        except FileNotFoundError:
            return None
        except Exception as e:
            log.error("Certificate loading failed (%s): %s", cert_path, str(e))
            return None

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

    def load_params(self, file_name):
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
                return dhparam_pem, ecparam_pem
        except Exception as e:
            log.error("param loading error: %s", str(e))
        return None, None

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
            log.info('Client key not present, generating\n')
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
                        raise Exception('Terms of service rejected.\n')
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

    @staticmethod
    def _is_wildcard_auth(authorization_resource):
        if hasattr(authorization_resource.body, 'wildcard'):
            return authorization_resource.body.wildcard
        if not AcmeManager._get_challenge(authorization_resource, 'http-01'):  # boulder not currently returning the wildcard field
            return True  # so if no http challenge, presume this is a wildcard auth
        return False

    def _handle_authorizations(self, order, fetch_only, domain_names):
        authorization_resources = {}

        for authorization_resource in order.authorizations:
            domain_name = ('*.' if (self._is_wildcard_auth(authorization_resource)) else '') + authorization_resource.body.identifier.value
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
        challenge_dns_responses = {}
        challenge_http_responses = {}
        for zone_name in domain_names:
            zone_responses = {}
            for domain_name in domain_names[zone_name]:
                if domain_name in authorization_resources:
                    authorization_resource = authorization_resources[domain_name]
                    identifier = authorization_resource.body.identifier.value
                    http_challenge_directory = self.config.http_challenge_directory(identifier, zone_name)
                    if http_challenge_directory:
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
                    else:
                        challenge_types[domain_name] = 'dns-01'
                        challenge = self._get_challenge(authorization_resource, challenge_types[domain_name])
                        if not challenge:
                            log.warning('Unable to use dns-01 challenge for %s', domain_name)
                            continue
                        response = challenge.validation(self.client_key)
                        zone_responses[domain_name] = ChallengeTuple(identifier, response)
                        log.debug('Setting DNS for _acme-challenge.%s = "%s"', domain_name, response)
                        self._add_hook('set_dns_challenge', zone=zone_name, domain=domain_name, challenge=response)
            if zone_responses:
                zone_key = self.config.zone_key(zone_name)
                if zone_key:
                    if self._set_dns_challenges(zone_name, zone_key, zone_responses):
                        challenge_dns_responses[zone_name] = zone_responses
                else:
                    try:
                        with open_file(self.config.filepath('challenge', zone_name), 'w', 0o644) as challenge_file:
                            json.dump({domain_name: response.response for domain_name, response in zone_responses.items()}, challenge_file)
                        challenge_dns_responses[zone_name] = zone_responses
                    except Exception as error:
                        log.warning('Unable to create acme-challenge file for zone %s: %s', zone_name, str(error))
                    if zone_name in challenge_dns_responses:
                        self._reload_zone(zone_name)
                self._add_hook('dns_zone_update', zone=zone_name)
            self._call_hooks()

        # wait for DNS propagation
        waiting = []
        for zone_name in challenge_dns_responses:
            name_servers = get_name_servers(zone_name)
            log.debug('Got name servers "%s" for %s', name_servers, zone_name)
            for name_server in name_servers:
                waiting += [DNSTuple(datetime.datetime.now(), name_server, domain_name,
                                     challenge_dns_responses[zone_name][domain_name].identifier, challenge_dns_responses[zone_name][domain_name].response, 0)
                            for domain_name in challenge_dns_responses[zone_name]]
        while waiting:
            when, name_server, domain_name, identifier, response, attempt_count = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if now < when:
                seconds = (when - now).seconds
                if 0 < seconds:
                    time.sleep(seconds)
            dns_challenges = lookup_dns_challenge(name_server, identifier)
            if response in dns_challenges:
                log.debug('Challenge present for %s at %s', domain_name, name_server)
            else:
                log.debug('Challenge missing for %s at %s', domain_name, name_server)
                if attempt_count < self.config.int('max_dns_lookup_attempts'):
                    heapq.heappush(waiting, DNSTuple(datetime.datetime.now() + datetime.timedelta(seconds=self.config.int('dns_lookup_delay')),
                                                     name_server, domain_name, identifier, response, attempt_count + 1))
                else:
                    log.warning('Maximum attempts reached waiting for DNS challenge %s at %s', domain_name, name_server)
        if challenge_dns_responses:
            time.sleep(2)

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

        # clear challenge responses
        for zone_name in challenge_dns_responses:
            log.debug('Removing DNS _acme-challenges for %s', zone_name)
            for domain_name, challenge in challenge_dns_responses[zone_name].items():
                self._add_hook('clear_dns_challenge', zone=zone_name, domain=domain_name, challenge=challenge.response)
            zone_key = self.config.zone_key(zone_name)
            if zone_key:
                self._remove_dns_challenges(zone_name, zone_key, challenge_dns_responses[zone_name])
            else:
                os.remove(self.config.filepath('challenge', zone_name))
                self._reload_zone(zone_name)
            self._add_hook('dns_zone_update', zone=zone_name)

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

    def _create_auth_order(self, domain_names):
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

    def process_authorizations(self, private_key_names=None):
        domain_names = collections.OrderedDict()

        # gather domain names from all specified certtificates
        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue
            for certificate_name, cert_spec in pk_spec.certificates.items():
                for zone_name, hosts in cert_spec.zones.items():
                    if zone_name not in domain_names:
                        domain_names[zone_name] = []
                    for domain_name in hosts:
                        if domain_name not in domain_names[zone_name]:
                            domain_names[zone_name].append(domain_name)

        # gather domain names from authorizations
        for zone_name, hosts in self.config.authorizations.items():
            if zone_name not in domain_names:
                domain_names[zone_name] = []
            for domain_name in hosts:
                if domain_name not in domain_names[zone_name]:
                    domain_names[zone_name].append(domain_name)

        authorization_groups = []
        for zone_name in domain_names:
            for host_name in domain_names[zone_name]:
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

    def process_certificates(self, auth_fetch_only, private_key_names=None):
        updated_key_zones = set()
        processed_keys = []

        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            log.debug('Processing private key %s', private_key_name)

            expiration_days = pk_spec.expiration_days

            rolled_private_key = False
            generated_private_key = False
            changed_private_key = False

            key_cipher_data = self.key_cipher_data(private_key_name)
            backup_keys = {}
            youngest_key_timestamp = 0
            oldest_key_timestamp = sys.maxsize
            try:
                for key_type in pk_spec.key_types:
                    backup_key_data = self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data)
                    if backup_key_data.timestamp:
                        youngest_key_timestamp = max(youngest_key_timestamp, backup_key_data.timestamp)
                        oldest_key_timestamp = min(oldest_key_timestamp, backup_key_data.timestamp)
                    backup_keys[key_type] = backup_key_data
            except PrivateKeyError as error:
                log.warning('Unable to load backup private key %s: %s', private_key_name, str(error))
                continue

            if 0 < youngest_key_timestamp:
                now = datetime.datetime.utcnow()
                oldest_key_age = (now - datetime.datetime.utcfromtimestamp(oldest_key_timestamp))
            else:
                oldest_key_age = None

            def _duration(prefix, days):
                if 0 < days:
                    return prefix + ('1 day' if (1 == days) else (str(days) + ' days'))
                return '' if (0 == days) else (_duration(' ', -days) + ' ago')

            if oldest_key_age is not None:
                log.debug('Private key due for rollover%s', _duration(' in ', expiration_days - oldest_key_age.days))

            rollover = False
            if (self.args.rollover
                    or (pk_spec.auto_rollover and self._need_to_rollover(oldest_key_age, expiration_days))):
                rollover = True

            try:
                keys = {key_type: self.load_private_key('private_key', private_key_name, key_type, key_cipher_data) for key_type in pk_spec.key_types}
            except PrivateKeyError as error:
                log.warning('Unable to load private key %s: %s', private_key_name, str(error))
                continue

            for key_type, options in pk_spec.key_options:
                if keys[key_type].key and not private_key_matches_options(key_type, keys[key_type].key, options):
                    log.info('Private %s key is not %s', key_type.upper(), private_key_descripton(key_type, options))
                    keys[key_type] = KeyData(None, None)

            for key_type in pk_spec.key_types:
                if backup_keys[key_type].key and (rollover or not keys[key_type].key):
                    keys[key_type] = backup_keys[key_type]
                    backup_keys[key_type] = KeyData(None, None)
                    rolled_private_key = True
                    self._add_hook('private_key_rollover', key_name=private_key_name, key_type=key_type,
                                   private_key_file=self.config.filepath('private_key', private_key_name, key_type),
                                   backup_key_file=self.config.filepath('backup_key', private_key_name, key_type),
                                   passphrase=key_cipher_data.passphrase if key_cipher_data else None)
            if rolled_private_key:
                log.info('Private key rolling over for %s', private_key_name)

            if not rolled_private_key and self._need_to_rollover(oldest_key_age, expiration_days):
                log.info('Backup key for %s has expired. Use "--rollover" to replace.', private_key_name)

            for key_type, options in pk_spec.key_options:
                if not keys[key_type].key:
                    log.info('Generating primary %s key for %s', key_type.upper(), private_key_name)
                    private_key = generate_private_key(key_type, options)
                    keys[key_type] = KeyData(private_key, None)
                    if private_key:
                        generated_private_key = True

            issued_certificates = []
            for certificate_name, cert_spec in pk_spec.certificates.items():
                log.debug('Processing certificate %s', certificate_name)

                issue_certificate_key_types = []
                for key_type in cert_spec.key_types:
                    if (key_type not in keys) or (not keys[key_type].key):
                        log.warning('No %s private key available for certificate %s', key_type.upper(), certificate_name, '\n')
                        continue

                    if (not rolled_private_key) and (not self.args.renew):
                        existing_certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if existing_certificate:
                            certificate_common_name = existing_certificate.get_subject().commonName
                            if cert_spec.common_name != certificate_common_name:
                                log.info('Common name changed for %s certificate %s from %s to %s', key_type.upper(), certificate_name,
                                             certificate_common_name, cert_spec.common_name)
                            else:
                                certificate_alt_names = get_alt_names(existing_certificate)
                                new_alt_names = set(cert_spec.alt_names)
                                existing_alt_names = set(certificate_alt_names)
                                if new_alt_names != existing_alt_names:
                                    added_alt_names = new_alt_names - existing_alt_names
                                    removed_alt_names = existing_alt_names - new_alt_names
                                    added = ', '.join([alt_name for alt_name in cert_spec.alt_names if (alt_name in added_alt_names)])
                                    removed = ', '.join([alt_name for alt_name in certificate_alt_names if (alt_name in removed_alt_names)])
                                    log.info('Alt names changed for %s certificate %s%s%s', key_type.upper(), certificate_name,
                                                 (', adding ' + added) if added else '', (', removing ' + removed) if removed else '')
                                else:
                                    if not private_key_matches_certificate(keys[key_type].key, existing_certificate):
                                        log.info('%s certificate %s public key does not match private key', key_type.upper(), certificate_name)
                                        changed_private_key = True
                                    else:
                                        cert_has_must_staple = has_oscp_must_staple(existing_certificate)
                                        if cert_has_must_staple != cert_spec.ocsp_must_staple:
                                            log.info('%s certificate %s %s ocsp_must_staple option',
                                                         key_type.upper(), certificate_name, 'has' if cert_has_must_staple else 'does not have')
                                        else:
                                            valid_duration = (datetime_from_asn1_generaltime(existing_certificate.get_notAfter()) - datetime.datetime.utcnow())
                                            if valid_duration.days < 0:
                                                log.info('%s certificate %s has expired', key_type.upper(), certificate_name)
                                            elif valid_duration.days < self.config.int('renewal_days'):
                                                log.info('%s certificate %s will expire in %s', key_type.upper(), certificate_name,
                                                             (str(valid_duration.days) + ' days') if valid_duration.days else 'less than a day')
                                            else:
                                                log.debug('%s certificate %s valid beyond renewal window', key_type.upper(), certificate_name)
                                                days_to_renew = valid_duration.days - self.config.int('renewal_days')
                                                log.debug('%s certificate due for renewal in %s %s', key_type.upper(), days_to_renew,
                                                              'day' if (1 == days_to_renew) else 'days')
                                                continue
                    issue_certificate_key_types.append(key_type)

                domain_names = collections.OrderedDict()
                for zone_name, hosts in cert_spec.zones.items():
                    if zone_name not in domain_names:
                        domain_names[zone_name] = []
                    for domain_name in hosts:
                        if domain_name not in domain_names[zone_name]:
                            domain_names[zone_name].append(domain_name)

                for key_type in issue_certificate_key_types:
                    csr_pem = generate_csr(keys[key_type].key, cert_spec.common_name, cert_spec.alt_names, cert_spec.ocsp_must_staple)
                    log.info('Requesting %s certificate for %s%s', key_type.upper(), cert_spec.common_name,
                                 (' with alt names: ' + ', '.join(cert_spec.alt_names)) if cert_spec.alt_names else '')
                    try:
                        order = self.acme_client.new_order(csr_pem)
                        self._handle_authorizations(order, auth_fetch_only, domain_names)
                        if order.uri:
                            order, response = self._poll_order(order)
                            if messages.STATUS_INVALID == order.body.status:
                                log.warning('Unable to issue %s certificate %s', key_type.upper(), certificate_name)
                                continue
                        order = self.acme_client.finalize_order(order,
                                                                datetime.datetime.now() + datetime.timedelta(
                                                                    seconds=self.config.int('cert_poll_time')))
                        certificate, chain = decode_full_chain(order.fullchain_pem)
                    except Exception as error:
                        log.warning('%s certificate issuance failed: %s', key_type.upper(), str(error))
                        if rolled_private_key:
                            issued_certificates = []  # do not partially install new certificates if private key changed
                            break
                        continue

                        log.debug('New %s certificate issued', key_type.upper())
                    issued_certificates.append(CertificateData(certificate_name, key_type, certificate, chain, cert_spec))

            processed_keys.append(PrivateKeyData(private_key_name, pk_spec.key_options, keys, backup_keys,
                                                 generated_private_key, rolled_private_key, changed_private_key, issued_certificates))

        # install keys and certificates
        root_certificates = self.load_root_certificates()

        for private_key_data in processed_keys:
            private_key_name = private_key_data.name
            pk_spec = self.config.private_keys[private_key_name]
            if (not private_key_data.issued_certificates) and (private_key_data.generated_key or private_key_data.rolled_key):
                log.warning('No certificates issued for private key %s. Skipping key updates', private_key_name)
                self._clear_hooks()
                continue

            generated_backup_key = False
            backup_keys = private_key_data.backup_keys
            for key_type, options in private_key_data.key_options:
                if not backup_keys[key_type].key:
                    log.info('Generating backup %s key for %s', key_type.upper(), private_key_name)
                    backup_keys[key_type] = KeyData(generate_private_key(key_type, options), None)
                    generated_backup_key = True

            transactions = []

            # save private keys
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in private_key_data.key_options:
                    if private_key_data.generated_key or private_key_data.rolled_key:
                        transactions.append(self.save_private_key('private_key', private_key_name, key_type,
                                                                  private_key_data.keys[key_type].key, key_cipher_data,
                                                                  timestamp=private_key_data.keys[key_type].timestamp))
                        self._add_hook('private_key_installed', key_name=private_key_name, key_type=key_type,
                                       private_key_file=self.config.filepath('private_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if key_cipher_data else None)
                    if generated_backup_key:
                        transactions.append(self.save_private_key('backup_key', private_key_name, key_type,
                                                                  backup_keys[key_type].key, key_cipher_data,
                                                                  timestamp=backup_keys[key_type].timestamp))
                        self._add_hook('backup_key_installed', key_name=private_key_name, key_type=key_type,
                                       backup_key_file=self.config.filepath('backup_key', private_key_name, key_type),
                                       passphrase=key_cipher_data.passphrase if key_cipher_data else None)
            except PrivateKeyError as error:
                log.warning('Unable to encrypt private key: %s', str(error))
                continue

            # verify DH and EC params for all certificates
            certificate_params = {}
            for certificate_name, cert_spec in pk_spec.certificates.items():
                generated_params = False
                if not (private_key_data.rolled_key or private_key_data.changed_key):
                    dhparam_pem, ecparam_pem = self.load_params(certificate_name)
                else:
                    dhparam_pem, ecparam_pem = (None, None)
                hold_dhparam_pem = dhparam_pem
                hold_ecparam_pem = ecparam_pem

                dhparam_size = cert_spec.dhparam_size
                if dhparam_pem and dhparam_size and (dhparam_size != get_dhparam_size(dhparam_pem)):
                    log.info('Diffie-Hellman parameters for %s are not %s bits', certificate_name, dhparam_size)
                    dhparam_pem = None
                if (not dhparam_pem) and dhparam_size:
                    log.info('Generating Diffie-Hellman parameters for %s', certificate_name)
                    dhparam_pem = generate_dhparam(dhparam_size)
                    if dhparam_pem:
                        generated_params = True
                    else:
                        log.warning('Diffie-Hellman parameters generation failed for %s bits', dhparam_size)
                        dhparam_pem = hold_dhparam_pem

                ecparam_curve = cert_spec.ecparam_curve
                if ecparam_pem and ecparam_curve and (ecparam_curve != get_ecparam_curve(ecparam_pem)):
                    log.info('Elliptical curve parameters for %s are not curve %s', certificate_name, ecparam_curve)
                    ecparam_pem = None
                if (not ecparam_pem) and ecparam_curve:
                    log.info('Generating elliptical curve parameters for %s', certificate_name)
                    ecparam_pem = generate_ecparam(ecparam_curve)
                    if ecparam_pem:
                        generated_params = True
                    else:
                        log.warning('Elliptical curve parameters generation failed for curve %s', ecparam_curve)
                        ecparam_pem = hold_ecparam_pem

                if ((dhparam_pem or ecparam_pem) and self.config.directory('param')
                        and (generated_params or not self.params_present(certificate_name, dhparam_pem, ecparam_pem))):
                    transactions.append(self.save_params(certificate_name, dhparam_pem, ecparam_pem))
                    self._add_hook('params_installed', key_name=private_key_name, certificate_name=certificate_name,
                                   params_file=self.config.filepath('param', certificate_name))
                certificate_params[certificate_name] = (dhparam_pem, ecparam_pem, generated_params)

            # save issued certificates
            saved_certificates = collections.OrderedDict()
            for certificate_data in private_key_data.issued_certificates:
                certificate_name = certificate_data.certificate_name
                dhparam_pem, ecparam_pem, generated_params = certificate_params[certificate_name]

                key_type = certificate_data.key_type
                if certificate_name not in saved_certificates:
                    saved_certificates[certificate_name] = []
                saved_certificates[certificate_name].append(key_type)

                transactions.append(self.save_certificate('certificate', certificate_name, key_type, certificate_data.certificate,
                                                          chain=certificate_data.chain,
                                                          dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                self._add_hook('certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                               certificate_file=self.config.filepath('certificate', certificate_name, key_type))
                if root_certificates[key_type] and self.config.directory('full_certificate'):
                    transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, certificate_data.certificate,
                                                              chain=certificate_data.chain, root_certificate=root_certificates[key_type],
                                                              dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                    self._add_hook('full_certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                   full_certificate_file=self.config.filepath('full_certificate', certificate_name, key_type))
                if certificate_data.chain and self.config.directory('chain'):
                    transactions.append(self.save_chain(certificate_name, key_type, certificate_data.chain))
                    self._add_hook('chain_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                   chain_file=self.config.filepath('chain', certificate_name, key_type))
                try:
                    if self.config.directory('full_key'):
                        transactions.append(self.save_private_key('full_key', certificate_name, key_type, private_key_data.keys[key_type].key, key_cipher_data,
                                                                  certificate=certificate_data.certificate, chain=certificate_data.chain,
                                                                  dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                        self._add_hook('full_key_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                       full_key_file=self.config.filepath('full_key', certificate_name, key_type))
                except PrivateKeyError as error:
                    log.warning('Unable to encrypt private key: %s', str(error))
                    continue

            # save any generated params for certs not issued
            for certificate_name in certificate_params:
                dhparam_pem, ecparam_pem, generated_params = certificate_params[certificate_name]
                if generated_params:
                    cert_spec = pk_spec.certificates[certificate_name]
                    for key_type in cert_spec.key_types:
                        if ((not private_key_data.keys[key_type].key)
                                or ((certificate_name in saved_certificates) and (key_type in saved_certificates[certificate_name]))):
                            continue
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if certificate:
                            if certificate_name not in saved_certificates:
                                saved_certificates[certificate_name] = []
                            saved_certificates[certificate_name].append(key_type)

                            chain = self.load_chain(certificate_name, key_type)

                            transactions.append(self.save_certificate('certificate', certificate_name, key_type, certificate,
                                                                      chain=chain,
                                                                      dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                            self._add_hook('certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                           certificate_file=self.config.filepath('certificate', certificate_name, key_type))
                            if root_certificates[key_type] and self.config.directory('full_certificate'):
                                transactions.append(self.save_certificate('full_certificate', certificate_name, key_type, certificate,
                                                                          chain=chain, root_certificate=root_certificates[key_type],
                                                                          dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                                self._add_hook('full_certificate_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                               full_certificate_file=self.config.filepath('full_certificate', certificate_name, key_type))
                            try:
                                if self.config.directory('full_key'):
                                    transactions.append(self.save_private_key('full_key', certificate_name, key_type,
                                                                              private_key_data.keys[key_type].key, key_cipher_data,
                                                                              certificate=certificate, chain=chain,
                                                                              dhparam_pem=dhparam_pem, ecparam_pem=ecparam_pem))
                                    self._add_hook('full_key_installed', key_name=private_key_name, key_type=key_type, certificate_name=certificate_name,
                                                   full_key_file=self.config.filepath('full_key', certificate_name, key_type))
                            except PrivateKeyError as error:
                                log.warning('Unable to encrypt %s private key %s: %s', key_type.upper(), private_key_name, str(error))
                                continue

            try:
                self._commit_file_transactions(transactions, archive_name=private_key_name)
                self._call_hooks()
                if private_key_data.generated_key or private_key_data.rolled_key or generated_backup_key:
                    log.info('Private keys for %s installed', private_key_name)
                for certificate_name in saved_certificates:
                    for key_type in saved_certificates[certificate_name]:
                        log.info('%s certificate %s installed', key_type.upper(), certificate_name)
                        cert_spec = pk_spec.certificates[certificate_name]
                        self.update_services(cert_spec.services)
                        self.update_certificate(certificate_name)
                        if not self.config.bool('follower_mode'):
                            for zone_name in cert_spec.zones:
                                if not self.config.zone_key(zone_name):
                                    updated_key_zones.add(zone_name)
                if generated_backup_key:  # reload services for all certificates
                    for certificate_name, cert_spec in pk_spec.certificates.items():
                        self.update_services(cert_spec.services)
                        self.update_certificate(certificate_name)

            except Exception as error:
                log.warning('Unable to install keys and certificates for %s: %s', private_key_name, str(error))
                self._clear_hooks()

        for zone_name in updated_key_zones:
            self._reload_zone(zone_name, critical=False)

    def revoke_certificates(self, private_key_names):
        updated_key_zones = set()
        updated_tlsa_zones = collections.OrderedDict()

        for private_key_name in private_key_names:
            if private_key_name in self.config.private_keys:
                pk_spec = self.config.private_keys[private_key_name]
                revoked_certificates = []
                certificate_count = 0
                for certificate_name, cert_spec in pk_spec.certificates.items():
                    for key_type in cert_spec.key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if certificate:
                            certificate_count += 1
                            try:
                                self.acme_client.revoke(josepy.ComparableX509(certificate), 0)
                                revoked_certificates.append((certificate_name, key_type))
                                log.info('%s certificate %s revoked', key_type.upper(), certificate_name)
                            except Exception as error:
                                log.warning('Unable to revoke %s certificate %s: %s', key_type.upper(), certificate_name, str(error))
                        else:
                            log.warning('%s certificate %s not found', key_type.upper(), certificate_name)

                archive_date = datetime.datetime.now()
                processed_tlsa = set()
                for certificate_name, key_type in revoked_certificates:
                    cert_spec = pk_spec.certificates[certificate_name]
                    self.archive_certificate('certificate', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_certificate('full_certificate', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_chain(certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_private_key('full_key', certificate_name, key_type, archive_name=private_key_name, archive_date=archive_date)
                    self.archive_params(certificate_name, archive_name=private_key_name, archive_date=archive_date)
                    for ct_log_name in cert_spec.ct_submit_logs:
                        self.archive_sct(certificate_name, key_type, ct_log_name, archive_name=private_key_name, archive_date=archive_date)

                    if not self.config.bool('follower_mode'):
                        for zone_name in cert_spec.zones:
                            if not self.config.zone_key(zone_name):
                                updated_key_zones.add(zone_name)
                    if certificate_name not in processed_tlsa:
                        processed_tlsa.add(certificate_name)

                        tlsa_records = cert_spec.tlsa_records
                        for zone_name in tlsa_records:
                            if self.config.zone_key(zone_name):
                                if zone_name not in updated_tlsa_zones:
                                    updated_tlsa_zones[zone_name] = []
                                updated_tlsa_zones[zone_name] += tlsa_data(get_list(tlsa_records, zone_name))
                            else:
                                log.warning('No update key configured for zone %s, unable to remove TLSA records', zone_name)

                if len(revoked_certificates) == certificate_count:
                    for key_type in pk_spec.key_types:
                        self.archive_private_key('private_key', private_key_name, key_type, archive_name=private_key_name, archive_date=archive_date)
            else:
                log.warning('%s is not a configured private key', private_key_name)

        for zone_name in updated_key_zones:
            self._reload_zone(zone_name, critical=False)
        for zone_name in updated_tlsa_zones:
            self._remove_tlsa_records(zone_name, self.config.zone_key(zone_name), updated_tlsa_zones[zone_name])

    def update_tlsa_records(self, private_key_names):
        tlsa_zones = collections.OrderedDict()

        root_certificates = list(self.load_root_certificates().values())

        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            keys = []
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in pk_spec.key_types:
                    keys.append((key_type, self.load_private_key('private_key', private_key_name, key_type, key_cipher_data).key))
                    keys.append((key_type, self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data).key))
            except PrivateKeyError as error:
                log.warning('Unable to load private key: %s', str(error))
                continue

            for certificate_name, cert_spec in pk_spec.certificates.items():
                tlsa_records = cert_spec.tlsa_records
                if tlsa_records:
                    certificates = []
                    chain = []
                    for key_type in cert_spec.key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if not certificate:
                            log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
                            continue
                        certificates.append(certificate)
                        chain += self.load_chain(certificate_name, key_type)

                    for zone_name in tlsa_records:
                        if self.config.zone_key(zone_name):
                            if zone_name not in tlsa_zones:
                                tlsa_zones[zone_name] = []
                            tlsa_zones[zone_name] += tlsa_data(get_list(tlsa_records, zone_name), certificates=certificates,
                                                               chain=(chain + root_certificates),
                                                               private_keys=[key for key_type, key in keys if (key_type in cert_spec.key_types)])
                        else:
                            log.warning('No update key configured for zone %s, unable to set TLSA records', zone_name)

        for zone_name in tlsa_zones:
            self._set_tlsa_records(zone_name, self.config.zone_key(zone_name), tlsa_zones[zone_name])
            self._add_hook('dns_zone_update', zone=zone_name)
        self._call_hooks()

    def update_signed_certificate_timestamps(self, private_key_names):
        if not self.config.directory('sct'):
            return

        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            transactions = []
            for certificate_name, cert_spec in pk_spec.certificates.items():
                if cert_spec.ct_submit_logs:
                    for key_type in cert_spec.key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        if certificate:
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
                                        self._add_hook('sct_installed', key_name=private_key_name, key_type=key_type,
                                                       certificate_name=certificate_name, ct_log_name=ct_log_name,
                                                       sct_file=self.config.filepath('sct', certificate_name, key_type, ct_log_name=ct_log_name))
                                        self.update_services(cert_spec.services)
                                        self.update_certificate(certificate_name)
                            else:
                                log.warning('%s certificate %s not found', key_type.upper(), certificate_name)

                try:
                    self._commit_file_transactions(transactions, archive_name=None)
                    self._call_hooks()
                except Exception as error:
                    log.warning('Unable to save Signed Certificate Timestamps for %s: %s', private_key_name, str(error))
                    self._clear_hooks()

    def update_ocsp_responses(self, private_key_names):
        if not self.config.directory('ocsp'):
            return

        root_certificates = self.load_root_certificates()

        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            transactions = []
            for certificate_name, cert_spec in pk_spec.certificates.items():
                # ignore ocsp if explicitly disabled for this certificate
                if not cert_spec.ocsp_responder_urls:
                    continue

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
                                        self._add_hook('ocsp_installed', key_name=private_key_name, key_type=key_type,
                                                       certificate_name=certificate_name,
                                                       ocsp_file=self.config.filepath('ocsp', certificate_name, key_type))
                                        self.update_services(cert_spec.services)
                                        self.update_certificate(certificate_name)
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

            try:
                self._commit_file_transactions(transactions, archive_name=None)
                self._call_hooks()
            except Exception as error:
                log.warning('Unable to save OCSP responses for %s: %s', private_key_name, str(error))
                self._clear_hooks()

    def _verify_certificate_installation(self, certificate_name, certificate, chain, key_type, host_name, port_number, starttls, cipher_list, protocol, keys):
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

    def verify_certificate_installation(self, private_key_names):
        key_type_ciphers = {}
        ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ssl_sock = OpenSSL.SSL.Connection(ssl_context, socket.socket())
        all_ciphers = ssl_sock.get_cipher_list()
        key_type_ciphers['rsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'RSA' in cipher_name]).encode('ascii')
        key_type_ciphers['ecdsa'] = ':'.join([cipher_name for cipher_name in all_ciphers if 'ECDSA' in cipher_name]).encode('ascii')

        for private_key_name, pk_spec in self.config.private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            keys = []
            key_cipher_data = self.key_cipher_data(private_key_name)
            try:
                for key_type in pk_spec.key_types:
                    keys.append((key_type, private_key_name, 'private', self.load_private_key('private_key', private_key_name, key_type, key_cipher_data).key))
                    keys.append((key_type, private_key_name, 'backup', self.load_private_key('backup_key', private_key_name, key_type, key_cipher_data).key))
            except PrivateKeyError as error:
                log.warning('Unable to load private key %s: %s', private_key_name, str(error))
                continue

            for certificate_name, cert_spec in pk_spec.certificates.items():
                verify_list = cert_spec.verify
                if verify_list:

                    for key_type in cert_spec.key_types:
                        certificate = self.load_certificate('certificate', certificate_name, key_type)
                        chain = self.load_chain(certificate_name, key_type)
                        if not certificate:
                            log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
                            continue

                        for verify in verify_list:
                            if verify.key_types and key_type not in verify.key_types:
                                continue
                            for host_name in verify.hosts or cert_spec.alt_names:
                                if host_name in cert_spec.alt_names:
                                    self._verify_certificate_installation(certificate_name, certificate, chain, key_type,
                                                                          host_name, verify['port'], verify['starttls'], key_type_ciphers[key_type],
                                                                          verify['protocol'], keys)

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
                    self.args.revoke or self.args.auth or self.args.certs or self.args.tlsa or self.args.sct or self.args.ocsp or self.args.symlink or self.args.verify)):
                self.args.auth = True
                self.args.certs = True
                self.args.tlsa = True
                self.args.sct = True
                self.args.ocsp = True
                self.args.symlink = True
                self.args.verify = True

            if self.args.revoke or self.args.auth or self.args.certs:
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
            if self.args.tlsa:
                self.update_tlsa_records(self.args.private_key_names)
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
            self.disconnect_client()
        finally:
            os.remove(pid_file_path)

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
                    log.debug("removing stall symlink '%s'", src)
                except FileNotFoundError:
                    pass

    def process_symlinks(self, private_key_names):
        if not self.config.directory('symlinks'):
            return

        private_keys = self.config.private_keys
        for private_key_name, pk_spec in private_keys.items():
            if private_key_names and (private_key_name not in private_key_names):
                continue

            for certificate_name, cert_spec in pk_spec.certificates.items():
                log.debug('Symlink certificate %s', certificate_name)

                # Create target directories
                root = self.config.directory('symlinks')
                alt_names = cert_spec.alt_names
                for alt_name in alt_names:
                    os.makedirs(os.path.join(root, alt_name), mode=0o755, exist_ok=True)

                target = self.config.filepath('param', certificate_name)
                self.process_symlink(alt_names, target, 'params.pem')

                for key_type in cert_spec.key_types:
                    # Private Keys
                    target = self.config.filepath('private_key', private_key_name, key_type)
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


def debug_hook(type, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import traceback
        import pdb
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()
