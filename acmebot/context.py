import datetime
import getpass
import os
import re
import sys
from typing import Optional, List, Tuple

import collections
from acme import messages, client
from cryptography.hazmat.primitives import serialization

from . import AcmeError, log, SUPPORTED_KEY_TYPES
from .config import CertificateSpec, FileManager
from .crypto import PrivateKey, Certificate, check_dhparam, check_ecparam
from .utils import makedir, archive_file

SCTData = collections.namedtuple('SCTData', ['version', 'id', 'timestamp', 'extensions', 'signature'])
KeyCipherData = collections.namedtuple('KeyCipherData', ['cipher', 'passphrase', 'forced'])


class CertParams(object):
    __slots__ = ('dhparams', 'ecparams')

    def __init__(self, dhparams: Optional[str], ecparams: Optional[str]):
        self.dhparams = dhparams
        self.ecparams = ecparams


class CertificateItem(object):
    __slots__ = ('type', 'params', 'context', 'updated', '_order', '_key', '_chain', '_certificate')

    UNINITIALIZED = 'uninitialized'

    def __init__(self, ty: str, params, context: 'CertificateContext'):
        self.type = ty
        self.params = params
        self.context = context
        self.updated = False

        self._order = self.UNINITIALIZED  # type: messages.OrderResource
        self._key = self.UNINITIALIZED  # type: Optional[PrivateKey]
        self._chain = self.UNINITIALIZED  # type: Optional[List[Certificate]]
        self._certificate = self.UNINITIALIZED  # type: Optional[Certificate]

    @property
    def name(self):
        return self.context.name

    @property
    def spec(self):
        return self.context.spec

    def order(self, acme_client: client.ClientV2, auth_only=False) -> messages.OrderResource:
        if self._order is self.UNINITIALIZED:
            if auth_only:
                key = PrivateKey.create(self.type, self.params)
            else:
                key = self.key
            csr = key.create_csr(self.spec.common_name, self.spec.alt_names, self.spec.ocsp_must_staple)
            self._order = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
            if auth_only:
                self._order.update(csr_pem=None)
        # make sure we are consistent when querying order
        assert auth_only or self._order.csr_pem is not None
        return self._order

    @property
    def key(self) -> PrivateKey:
        if self._key is self.UNINITIALIZED:
            self._key = self._load_key()
            if not self._key:
                log.debug("[%s] generating %s private key", self.name, self.type.upper())
                self._key = PrivateKey.create(self.type, self.params)
                self.updated = True
        return self._key

    def _load_key(self) -> Optional[PrivateKey]:
        key_file_path = self.context.fs.filepath('private_key', self.name, self.type)
        try:
            return PrivateKey.load(key_file_path, lambda: self.context.key_cipher(force_prompt=True).passphrase)
        except Exception as e:
            raise AcmeError("private key '{}' loading failed", key_file_path) from e

    @property
    def certificate(self) -> Certificate:
        if self._certificate is self.UNINITIALIZED:
            self._certificate = self._load_certificate()
        return self._certificate

    @certificate.setter
    def certificate(self, value: Certificate):
        assert self._certificate is not value
        self._certificate = value
        self.updated = True

    def _load_certificate(self):
        cert_path = self.context.fs.filepath('certificate', self.name, self.type)
        try:
            return Certificate.load(cert_path)
        except Exception as e:
            raise AcmeError("certificate '{}' loading failed", cert_path) from e

    def should_renew(self, renewal_days: int):
        key = self.key
        certificate = self.certificate
        if self.updated or not certificate:
            return True

        if key.params != self.params:
            log.info('[%s:%s] Private key is not %s', self.name, self.type.upper(), str(key))
            return True

        if self.spec.common_name != certificate.common_name:
            log.info('[%s:%s] Common name changed from %s to %s', self.name, self.type.upper(),
                     certificate.common_name, self.spec.common_name)
            return True

        new_alt_names = set(self.spec.alt_names)
        existing_alt_names = set(certificate.alt_names)
        if new_alt_names != existing_alt_names:
            added_alt_names = new_alt_names - existing_alt_names
            removed_alt_names = existing_alt_names - new_alt_names
            added = ', '.join([alt_name for alt_name in self.spec.alt_names if (alt_name in added_alt_names)])
            removed = ', '.join([alt_name for alt_name in certificate.alt_names if (alt_name in removed_alt_names)])
            log.info('[%s:%s] Alt names changed%s%s', self.name, self.type.upper(),
                     (', adding ' + added) if added else '', (', removing ' + removed) if removed else '')
            return True

        if not key.match_certificate(certificate):
            log.info('[%s:%s] certificate public key does not match private key', self.name, self.type.upper())
            return True

        if certificate.has_oscp_must_staple != self.spec.ocsp_must_staple:
            log.info('[%s:%s] certificate %s ocsp_must_staple option', self.name, self.type.upper(),
                     'has' if certificate.has_oscp_must_staple else 'does not have')
            return True

        valid_duration = (certificate.not_after - datetime.datetime.utcnow())
        if valid_duration.days < 0:
            log.info('[%s:%s] certificate has expired', self.name, self.type.upper())
            return True
        if valid_duration.days < renewal_days:
            log.info('[%s:%s] certificate will expire in %s', self.name, self.type.upper(),
                     (str(valid_duration.days) + ' days') if valid_duration.days else 'less than a day')
            return True

        days_to_renew = valid_duration.days - renewal_days
        log.debug('[%s:%s] certificate valid beyond renewal window (renew in %s %s)', self.name, self.type.upper(),
                  days_to_renew, 'day' if (1 == days_to_renew) else 'days')
        return False

    def archive_file(self, file_type, archive_date: datetime.datetime, **kwargs):
        self.context.archive_file(file_type, archive_date, key_type=self.type, **kwargs)


class CertificateContext(object):

    # __slots__ = ('name', 'spec', 'params', 'params_updated', 'certificates')

    def __init__(self, spec: CertificateSpec, fs: FileManager):
        self.spec = spec
        self.fs = fs

        self._params = None
        self.params_updated = False

        pkey = spec.private_key
        self._items = [CertificateItem(key_type, pkey.params(key_type), self) for key_type in spec.key_types]  # type: List[CertificateItem]

        self._transactions = []
        self._key_cipher = None  # type: Optional[KeyCipherData]

    def __iter__(self):
        return self._items.__iter__()

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def updated(self) -> bool:
        return self.params_updated or any(item.updated for item in self._items)

    @property
    def params(self) -> CertParams:
        if self._params is None:
            self._params = self._load_params()
        return self._params

    # used to force refresh params
    def reset_params(self):
        self._params = CertParams(None, None)

    @property
    def domain_names(self):
        return self.spec.alt_names

    def key_cipher(self, force_prompt=False) -> Optional[KeyCipherData]:
        if self._key_cipher:
            return self._key_cipher if self._key_cipher.cipher else None

        passphrase = self.spec.private_key.passphrase
        if (passphrase is True) or (force_prompt and not passphrase):
            passphrase = os.getenv('{cert}_PASSPHRASE'.format(cert=self.name.replace('.', '_').upper()))
            if not passphrase:
                if sys.stdin.isatty():
                    passphrase = getpass.getpass('Enter private key password for {name}: '.format(name=self.name))
                else:
                    passphrase = sys.stdin.readline().strip()
            # TODO: what to do if not passphrase at this point ?
        self._key_cipher = KeyCipherData(self.spec.private_key.cipher, passphrase, force_prompt) if passphrase else KeyCipherData(None, None, False)
        return self._key_cipher if self._key_cipher.cipher else None

    def _load_params(self) -> CertParams:
        pem_data = None
        if self.fs.directory('param'):
            param_file_path = self.fs.filepath('param', self.name)
            try:
                with open(param_file_path, 'rb') as f:
                    pem_data = f.read()
            except FileNotFoundError:
                pass
        if not pem_data:
            for key_type in SUPPORTED_KEY_TYPES:
                certificate_file_path = self.fs.filepath('certificate', self.name, key_type)
                try:
                    with open(certificate_file_path, 'rb') as f:
                        pem_data = f.read()
                    break
                except FileNotFoundError:
                    pass
            else:
                return CertParams(None, None)
        if pem_data:
            match = re.match(br'.*(-----BEGIN DH PARAMETERS-----.*-----END DH PARAMETERS-----)', pem_data, re.DOTALL)
            dhparam_pem = (match.group(1) + b'\n') if match else None
            match = re.match(br'.*(-----BEGIN EC PARAMETERS-----.*-----END EC PARAMETERS-----)', pem_data, re.DOTALL)
            ecparam_pem = (match.group(1) + b'\n') if match else None
            if not check_dhparam(dhparam_pem):
                dhparam_pem = None
            if not check_ecparam(ecparam_pem):
                ecparam_pem = None
            return CertParams(dhparam_pem, ecparam_pem)
        return CertParams(None, None)

    def archive_file(self, file_type, archive_date=datetime.datetime.now(), **kwargs) -> Optional[Tuple[str, str]]:
        file_path = self.fs.filepath(file_type, self.name, **kwargs)
        archive_dir = self.fs.archive_dir(self.name)
        return archive_file(file_type, file_path, archive_dir, archive_date)
