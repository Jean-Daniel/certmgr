import datetime
import getpass
import os
import re
import struct
import sys
from typing import Optional, List, Tuple

import collections
from asn1crypto import ocsp

from certlib.utils import FileTransaction, FileOwner
from . import AcmeError, log, SUPPORTED_KEY_TYPES
from .config import CertificateSpec, FileManager, SCTLog
from .crypto import PrivateKey, Certificate, check_dhparam, check_ecparam, load_full_chain_file, save_chain
from .ocsp import load_ocsp_response
from .utils import archive_file, SCTData

KeyCipherData = collections.namedtuple('KeyCipherData', ['passphrase', 'forced'])

_UNINITIALIZED = 'uninitialized'


class CertificateItem(object):
    __slots__ = ('type', 'params', 'context',
                 '_scts', '_ocsp_response', '_ocsp_response_updated',
                 '_key', '_chain', '_certificate', '_certificate_updated')

    def __init__(self, ty: str, params, context: 'CertificateContext'):
        self.type = ty
        self.params = params
        self.context = context

        self._scts = {}

        self._ocsp_response = _UNINITIALIZED  # type: Optional[ocsp.OCSPResponse]
        self._ocsp_response_updated = False

        self._key = _UNINITIALIZED  # type: Optional[PrivateKey]
        self._chain = _UNINITIALIZED  # type: Optional[List[Certificate]]
        self._certificate = _UNINITIALIZED  # type: Optional[Certificate]
        self._certificate_updated = False

    @property
    def name(self):
        return self.context.name

    @property
    def spec(self):
        return self.context.spec

    @property
    def updated(self):
        return self._certificate_updated or self._ocsp_response_updated or any(sct[1] for sct in self._scts.values())

    @property
    def key(self) -> PrivateKey:
        if self._key is _UNINITIALIZED:
            self._key = self._load_key()
        return self._key

    def save_key(self, owner: FileOwner, with_certificate: bool = False) -> Optional[FileTransaction]:
        file_type = 'full_key' if with_certificate else 'private_key'
        key_path = self.context.fs.filepath(file_type, self.name, self.type)
        if not key_path:
            return None

        key_cipher_data = self.context.key_cipher()
        password = key_cipher_data.passphrase if key_cipher_data and not key_cipher_data.forced else None
        with FileTransaction(file_type, key_path, chmod=0o640, owner=owner) as trx:
            trx.write(self.key.encode(password))
            if with_certificate:
                trx.write(b'\n')
                self.certificate.dump(trx, self.chain, self.context.dhparams, self.context.ecparams)
        return trx

    def _load_key(self) -> Optional[PrivateKey]:
        key_file_path = self.context.fs.filepath('private_key', self.name, self.type)
        try:
            return PrivateKey.load(key_file_path, lambda: self.context.key_cipher(force_prompt=True).passphrase)
        except Exception as e:
            raise AcmeError("private key '{}' loading failed", key_file_path) from e

    @property
    def certificate(self) -> Certificate:
        if self._certificate is _UNINITIALIZED:
            self._load_certificate_and_chain()
        return self._certificate

    def save_certificate(self, owner: FileOwner, root: Optional[Certificate] = None) -> Optional[FileTransaction]:
        file_type = 'full_certificate' if root else 'certificate'
        cert_path = self.context.fs.filepath(file_type, self.name, self.type)
        if not cert_path:
            return None
        with FileTransaction(file_type, cert_path, chmod=0o644, owner=owner) as trx:
            self.certificate.dump(trx, self.chain, self.context.dhparams, self.context.ecparams, root)
        return trx

    @property
    def chain(self) -> List[Certificate]:
        if self._chain is _UNINITIALIZED:
            self._load_certificate_and_chain()
        return self._chain

    def save_chain(self, owner: FileOwner) -> Optional[FileTransaction]:
        chain_path = self.context.fs.filepath('chain', self.name, self.type)
        if not chain_path:
            return None
        with FileTransaction('chain', chain_path, chmod=0o644, owner=owner) as trx:
            save_chain(trx, self.chain)
        return trx

    def update(self, key: PrivateKey, cert: Certificate, chain: List[Certificate]):
        self._certificate_updated = self._key is not key or self._certificate is not cert or self._chain is not chain
        self._certificate = cert
        self._chain = chain
        self._key = key

    @property
    def certificate_updated(self):
        return self._certificate_updated

    def _load_certificate_and_chain(self):
        cert_path = self.context.fs.filepath('certificate', self.name, self.type)
        try:
            certificate, chain = load_full_chain_file(cert_path)
            if self._certificate is _UNINITIALIZED:
                self._certificate = certificate

            if self._chain is _UNINITIALIZED:
                self._chain = chain
        except Exception as e:
            raise AcmeError("certificate '{}' loading failed", cert_path) from e

    def should_renew(self, renewal_days: int):
        if not self.key or not self.certificate:
            return True

        key = self.key
        if key.params != self.params:
            log.info('[%s:%s] Private key is not %s', self.name, self.type.upper(), str(key))
            return True

        certificate = self.certificate
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

    @property
    def ocsp_response(self) -> Optional[ocsp.OCSPResponse]:
        if self._ocsp_response is _UNINITIALIZED:
            self._ocsp_response = load_ocsp_response(self.context.fs.filepath('ocsp', self.name, self.type))

        return self._ocsp_response

    @ocsp_response.setter
    def ocsp_response(self, value: Optional[ocsp.OCSPResponse]):
        self._ocsp_response_updated = self._ocsp_response is not value
        self._ocsp_response = value

    @property
    def ocsp_updated(self):
        return self._ocsp_response_updated

    def save_ocsp(self, owner: FileOwner) -> Optional[FileTransaction]:
        file_path = self.context.fs.filepath('ocsp', self.name, self.type)
        if not file_path:
            return None
        ocsp_response = self.ocsp_response
        if ocsp_response:
            with FileTransaction('ocsp', file_path, chmod=0o644, owner=owner) as trx:
                trx.write(self.ocsp_response.dump())
            return trx
        else:
            # TODO: archive existing response
            return None

    def sct(self, ct_log: SCTLog) -> Tuple[Optional[SCTData], bool]:
        if ct_log.name not in self._scts:
            self._scts[ct_log.name] = self._load_sct(ct_log), False
        return self._scts[ct_log.name]

    def update_sct(self, ct_log: SCTLog, sct_data: SCTData):
        self._scts[ct_log.name] = sct_data, sct_data != self._scts.get(ct_log.name)

    def save_sct(self, ct_log: SCTLog, owner: FileOwner) -> Optional[FileTransaction]:
        file_path = self.context.fs.filepath('sct', self.name, self.type, ct_log_name=ct_log.name)
        if not file_path:
            return None
        sct_data, _ = self.sct(ct_log)
        if sct_data:
            with FileTransaction('sct', file_path, chmod=0o644, owner=owner) as trx:
                sct = struct.pack('>b32sQH', sct_data.version, sct_data.id, sct_data.timestamp, len(sct_data.extensions))
                trx.write(sct)
                if sct_data.extensions:
                    trx.write(sct_data.extensions)
                if sct_data.signature:
                    trx.write(sct_data.signature)
            return trx
        else:
            # TODO: archive existing data
            return None

    def _load_sct(self, ct_log: SCTLog) -> Optional[SCTData]:
        try:
            sct_file_path = self.context.fs.filepath('sct', self.name, self.type, ct_log_name=ct_log.name)
            with open(sct_file_path, 'rb') as sct_file:
                sct = sct_file.read()
                version, logid, timestamp, extensions_len = struct.unpack('>b32sQH', sct[:43])
                extensions = sct[43:(43 + extensions_len)] if extensions_len else b''
                signature = sct[43 + extensions_len:]

                if ct_log.id == logid:
                    return SCTData(version, logid, timestamp, extensions, signature)
                else:
                    log.debug('[%s:%s] SCT "%s" does not match log id for "%s"', self.name, self.type, sct_file_path, ct_log.name)
        except FileNotFoundError:
            return None
        except Exception as e:
            log.warning("[%s:%s] error loading sct log '%s': %s", self.name, self.type, ct_log.name, str(e))
        return None

    def archive_file(self, file_type, archive_date: datetime.datetime, **kwargs):
        self.context.archive_file(file_type, archive_date, key_type=self.type, **kwargs)


class CertificateContext(object):

    # __slots__ = ('name', 'spec', 'params', 'params_updated', 'certificates')

    def __init__(self, spec: CertificateSpec, fs: FileManager):
        self.spec = spec
        self.fs = fs

        self._dhparams = _UNINITIALIZED  # type: bytes
        self._ecparams = _UNINITIALIZED  # type: bytes
        self._params_updated = False

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
        return self._params_updated or any(item.updated for item in self._items)

    @property
    def dhparams(self) -> Optional[bytes]:
        if self._dhparams is _UNINITIALIZED:
            self._dhparams, self._ecparams = self._load_params()
        return self._dhparams

    @property
    def ecparams(self) -> Optional[bytes]:
        if self._ecparams is _UNINITIALIZED:
            self._dhparams, self._ecparams = self._load_params()
        return self._ecparams

    @property
    def params_updated(self):
        return self._params_updated

    def save_params(self, owner: FileOwner) -> Optional[FileTransaction]:
        param_file = self.fs.filepath('param', self.name)
        if not param_file:
            return None
        dhparams = self._dhparams
        ecparams = self._ecparams
        if dhparams or ecparams:
            with FileTransaction('param', param_file, chmod=0o640, owner=owner) as transaction:
                if dhparams and ecparams:
                    transaction.write(dhparams + b'\n' + ecparams)
                else:
                    transaction.write(dhparams or ecparams)
            return transaction
        # TODO: transaction that archive file only
        return None

    def update(self, dhparams: Optional[bytes], ecparams: Optional[bytes]):
        self._params_updated = dhparams != self._dhparams or ecparams != self._ecparams
        self._dhparams = dhparams
        self._ecparams = ecparams

    @property
    def domain_names(self):
        return self.spec.alt_names

    def key_cipher(self, force_prompt=False) -> Optional[KeyCipherData]:
        if self._key_cipher:
            return self._key_cipher if self._key_cipher.passphrase else None

        passphrase = self.spec.private_key.passphrase
        if (passphrase is True) or (force_prompt and not passphrase):
            passphrase = os.getenv('{cert}_PASSPHRASE'.format(cert=self.name.replace('.', '_').upper()))
            if not passphrase:
                if sys.stdin.isatty():
                    passphrase = getpass.getpass('Enter private key password for {name}: '.format(name=self.name))
                else:
                    passphrase = sys.stdin.readline().strip()
            # TODO: what to do if no passphrase at this point ?
        self._key_cipher = KeyCipherData(passphrase.encode("utf-8"), force_prompt) if passphrase else KeyCipherData(None, False)
        return self._key_cipher if self._key_cipher.passphrase else None

    def _load_params(self) -> Tuple[Optional[bytes], Optional[bytes]]:
        pem_data = None
        param_file_path = self.fs.filepath('param', self.name)
        if param_file_path:
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
                return None, None

        if not pem_data:
            return None, None

        match = re.match(br'.*(-----BEGIN DH PARAMETERS-----.*-----END DH PARAMETERS-----)', pem_data, re.DOTALL)
        dhparam_pem = (match.group(1) + b'\n') if match else None
        match = re.match(br'.*(-----BEGIN EC PARAMETERS-----.*-----END EC PARAMETERS-----)', pem_data, re.DOTALL)
        ecparam_pem = (match.group(1) + b'\n') if match else None
        if dhparam_pem and not check_dhparam(dhparam_pem):
            dhparam_pem = None
        if ecparam_pem and not check_ecparam(ecparam_pem):
            ecparam_pem = None
        return dhparam_pem, ecparam_pem

    def archive_file(self, file_type, archive_date=datetime.datetime.now(), **kwargs) -> Optional[Tuple[str, str]]:
        file_path = self.fs.filepath(file_type, self.name, **kwargs)
        archive_dir = self.fs.archive_dir(self.name)
        return archive_file(file_type, file_path, archive_dir, archive_date)