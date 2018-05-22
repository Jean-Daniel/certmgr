import contextlib
import datetime
import os
import re
import struct
from typing import List, Optional, Tuple

from certlib.utils import get_key_cipher
from . import AcmeError
from .config import CertificateDef
from .crypto import Certificate, PrivateKey, check_dhparam, check_ecparam, load_full_chain_file, save_chain
from .logging import log
from .ocsp import OCSP
from .sct import SCTData, SCTLog
from .utils import ArchiveAndWriteOperation, FileOwner, KeyCipherData, WriteOperation

_UNINITIALIZED = 'uninitialized'


class CertificateItem(object):
    __slots__ = ('type', 'params', 'context', 'data_dir',
                 '_scts', '_ocsp_response', '_ocsp_response_updated',
                 '_key', '_chain', '_certificate', '_certificate_updated')

    def __init__(self, ty: str, params, context: 'CertificateContext'):
        self.type = ty
        self.params = params
        self.context = context
        self.data_dir = os.path.join(context.data_dir, ty)

        self._scts = {}

        self._ocsp_response = _UNINITIALIZED  # type: Optional[OCSP]
        self._ocsp_response_updated = False

        self._key = _UNINITIALIZED  # type: Optional[PrivateKey]
        self._chain = _UNINITIALIZED  # type: Optional[List[Certificate]]
        self._certificate = _UNINITIALIZED  # type: Optional[Certificate]
        self._certificate_updated = False

    @property
    def name(self):
        return self.context.name

    @property
    def config(self):
        return self.context.config

    @property
    def updated(self):
        return self._certificate_updated or self._ocsp_response_updated or any(sct[1] for sct in self._scts.values())

    @property
    def key(self) -> PrivateKey:
        if self._key is _UNINITIALIZED:
            self._key = self._load_key()
        return self._key

    def key_path(self, full=False):
        return os.path.join(self.data_dir, 'keys', 'key+cert.pem' if full else 'key.pem')

    def save_key(self, owner: FileOwner, archive: bool = True, with_certificate: bool = False) -> Optional[WriteOperation]:
        key_path = self.key_path(full=with_certificate)
        if not key_path:
            return None

        key_cipher_data = self.context.key_cipher()
        password = key_cipher_data.passphrase if key_cipher_data and not key_cipher_data.forced else None
        if archive:
            op = ArchiveAndWriteOperation('keys', key_path, mode=0o640, owner=owner)
        else:
            op = WriteOperation(key_path, mode=0o640, owner=owner)
        with op.file() as f:
            f.write(self.key.encode(password))
            if with_certificate:
                f.write(b'\n')
                self.certificate.dump(f, self.chain, self.context.dhparams, self.context.ecparams)
        return op

    def _load_key(self) -> Optional[PrivateKey]:
        key_file_path = self.key_path()
        try:
            return PrivateKey.load(key_file_path, lambda: self.context.key_cipher(force_prompt=True).passphrase)
        except Exception as e:
            log.raise_error("private key '%s' loading failed", key_file_path, cause=e)

    @property
    def certificate(self) -> Certificate:
        if self._certificate is _UNINITIALIZED:
            self._load_certificate_and_chain()
        return self._certificate

    def certificate_path(self, full=False):
        return os.path.join(self.data_dir, 'cert+root.pem' if full else 'cert.pem')

    def save_certificate(self, owner: FileOwner, root: Optional[Certificate] = None) -> Optional[WriteOperation]:
        cert_path = self.certificate_path(full=root is not None)
        if not cert_path:
            return None
        op = ArchiveAndWriteOperation('certificates', cert_path, mode=0o644, owner=owner)
        with op.file() as f:
            self.certificate.dump(f, self.chain, self.context.dhparams, self.context.ecparams, root)
        return op

    @property
    def chain(self) -> List[Certificate]:
        if self._chain is _UNINITIALIZED:
            self._load_certificate_and_chain()
        return self._chain

    def chain_path(self):
        return os.path.join(self.data_dir, 'chain.pem')

    def save_chain(self, owner: FileOwner) -> Optional[WriteOperation]:
        chain_path = self.chain_path()
        if not chain_path:
            return None
        op = ArchiveAndWriteOperation('certificates', chain_path, mode=0o644, owner=owner)
        with op.file() as f:
            save_chain(f, self.chain)
        return op

    def update(self, key: PrivateKey, cert: Certificate, chain: List[Certificate]):
        self._certificate_updated = self._key is not key or self._certificate is not cert or self._chain is not chain
        self._certificate = cert
        self._chain = chain
        self._key = key

    @property
    def certificate_updated(self):
        return self._certificate_updated

    def _load_certificate_and_chain(self):
        cert_path = self.certificate_path()
        try:
            certificate, chain = load_full_chain_file(cert_path)
            if self._certificate is _UNINITIALIZED:
                self._certificate = certificate

            if self._chain is _UNINITIALIZED:
                self._chain = chain
        except Exception as e:
            log.raise_error("certificate '%s' loading failed", cert_path, cause=e)

    def should_renew(self, renewal_days: int):
        if not self.key or not self.certificate:
            return True

        key = self.key
        if key.params != self.params:
            log.info('Private key is not %s', str(key))
            return True

        certificate = self.certificate
        if self.config.common_name != certificate.common_name:
            log.info('Common name changed from %s to %s', certificate.common_name, self.config.common_name)
            return True

        new_alt_names = set(self.config.alt_names)
        existing_alt_names = set(certificate.alt_names)
        if new_alt_names != existing_alt_names:
            added_alt_names = new_alt_names - existing_alt_names
            removed_alt_names = existing_alt_names - new_alt_names
            added = ', '.join([alt_name for alt_name in self.config.alt_names if (alt_name in added_alt_names)])
            removed = ', '.join([alt_name for alt_name in certificate.alt_names if (alt_name in removed_alt_names)])
            log.info('Alt names changed%s%s', (', adding ' + added) if added else '', (', removing ' + removed) if removed else '')
            return True

        if not key.match_certificate(certificate):
            log.info('certificate public key does not match private key')
            return True

        if certificate.has_oscp_must_staple != self.config.ocsp_must_staple:
            log.info('certificate %s ocsp_must_staple option', 'has' if certificate.has_oscp_must_staple else 'does not have')
            return True

        valid_duration = (certificate.not_after - datetime.datetime.utcnow())
        if valid_duration.days < 0:
            log.info('certificate has expired')
            return True
        if valid_duration.days < renewal_days:
            log.info('certificate will expire in %s', (str(valid_duration.days) + ' days') if valid_duration.days else 'less than a day')
            return True

        days_to_renew = valid_duration.days - renewal_days
        log.debug('certificate valid beyond renewal window (renew in %s %s)', days_to_renew, 'day' if (1 == days_to_renew) else 'days')
        return False

    @property
    def ocsp_response(self) -> Optional[OCSP]:
        if self._ocsp_response is _UNINITIALIZED:
            self._ocsp_response = OCSP.load(self.ocsp_path())

        return self._ocsp_response

    @ocsp_response.setter
    def ocsp_response(self, value: Optional[OCSP]):
        self._ocsp_response_updated = self.ocsp_response is not value
        self._ocsp_response = value

    @property
    def ocsp_updated(self):
        return self._ocsp_response_updated

    def ocsp_path(self):
        return os.path.join(self.data_dir, 'oscp.der')

    def save_ocsp(self, owner: FileOwner) -> Optional[WriteOperation]:
        file_path = self.ocsp_path()
        if not file_path:
            return None
        ocsp_response = self.ocsp_response
        op = ArchiveAndWriteOperation('meta', file_path, mode=0o644, owner=owner)
        if ocsp_response:
            with op.file() as f:
                f.write(ocsp_response.encode())
        return op

    def sct(self, ct_log: SCTLog) -> Tuple[Optional[SCTData], bool]:
        if ct_log.name not in self._scts:
            self._scts[ct_log.name] = self._load_sct(ct_log), False
        return self._scts[ct_log.name]

    def update_sct(self, ct_log: SCTLog, sct_data: SCTData):
        self._scts[ct_log.name] = sct_data, sct_data != self._scts.get(ct_log.name)

    def sct_path(self, ct_log: SCTLog):
        return os.path.join(self.data_dir, 'scts', ct_log.name + '.sct')

    def save_sct(self, ct_log: SCTLog, owner: FileOwner) -> Optional[WriteOperation]:
        file_path = self.sct_path(ct_log)
        if not file_path:
            return None
        sct_data, _ = self.sct(ct_log)
        op = ArchiveAndWriteOperation('meta', file_path, mode=0o644, owner=owner)
        if sct_data:
            with op.file() as f:
                sct = struct.pack('>b32sQH', sct_data.version, sct_data.id, sct_data.timestamp, len(sct_data.extensions))
                f.write(sct)
                if sct_data.extensions:
                    f.write(sct_data.extensions)
                if sct_data.signature:
                    f.write(sct_data.signature)
        return op

    def _load_sct(self, ct_log: SCTLog) -> Optional[SCTData]:
        try:
            sct_file_path = self.sct_path(ct_log)
            with open(sct_file_path, 'rb') as sct_file:
                sct = sct_file.read()
                version, logid, timestamp, extensions_len = struct.unpack('>b32sQH', sct[:43])
                extensions = sct[43:(43 + extensions_len)] if extensions_len else b''
                signature = sct[43 + extensions_len:]

                if ct_log.id == logid:
                    return SCTData(version, logid, timestamp, extensions, signature)
                else:
                    log.debug('SCT "%s" does not match log id for "%s"', sct_file_path, ct_log.name)
        except FileNotFoundError:
            return None
        except Exception as e:
            log.warning("error loading sct log '%s': %s", ct_log.name, str(e))
        return None


class CertificateContext(object):

    # __slots__ = ('name', 'spec', 'params', 'params_updated', 'certificates')

    def __init__(self, config: CertificateDef, data_dir: str):
        self.config = config
        self.data_dir = os.path.join(data_dir, config.name)

        self._dhparams = _UNINITIALIZED  # type: bytes
        self._ecparams = _UNINITIALIZED  # type: bytes
        self._params_updated = False

        pkey = config.private_key
        self._items = [CertificateItem(key_type, pkey.params(key_type), self) for key_type in config.key_types]  # type: List[CertificateItem]

        self._key_cipher = _UNINITIALIZED  # type: Optional[KeyCipherData]

    def __iter__(self):
        return self._items.__iter__()

    @property
    def updated(self) -> bool:
        return self._params_updated or any(item.updated for item in self._items)

    @property
    def dhparams(self) -> Optional[bytes]:
        if self._dhparams is _UNINITIALIZED:
            self._load_params()
        return self._dhparams

    @property
    def ecparams(self) -> Optional[bytes]:
        if self._ecparams is _UNINITIALIZED:
            self._load_params()
        return self._ecparams

    @property
    def params_path(self):
        return os.path.join(self.data_dir, 'params.pem')

    @property
    def params_updated(self):
        return self._params_updated

    def save_params(self, owner: FileOwner) -> Optional[WriteOperation]:
        param_file = self.params_path

        dhparams = self._dhparams
        ecparams = self._ecparams
        op = ArchiveAndWriteOperation('certificates', param_file, mode=0o640, owner=owner)
        if dhparams or ecparams:
            with op.file() as f:
                if dhparams and ecparams:
                    f.write(dhparams + b'\n' + ecparams)
                else:
                    f.write(dhparams or ecparams)
        return op

    def update(self, dhparams: Optional[bytes], ecparams: Optional[bytes]):
        if not dhparams and not ecparams:
            # in case they are both None, we have to know if the params exists to properly set the update flag.
            self._load_params()
        self._params_updated = dhparams != self._dhparams or ecparams != self._ecparams
        self._dhparams = dhparams
        self._ecparams = ecparams

    @property
    def name(self) -> str:
        return self.config.common_name

    @property
    def common_name(self) -> str:
        return self.config.common_name

    @property
    def alt_names(self):
        return self.config.alt_names

    @property
    def domain_names(self):
        return self.config.alt_names

    def key_cipher(self, force_prompt=False) -> Optional[KeyCipherData]:
        if self._key_cipher is _UNINITIALIZED:
            self._key_cipher = get_key_cipher(self.name, self.config.private_key.passphrase, force_prompt)
        return self._key_cipher

    def _load_params(self):
        self._dhparams = self._ecparams = None

        pem_data = None
        param_file_path = self.params_path
        with contextlib.suppress(FileNotFoundError):
            with open(param_file_path, 'rb') as f:
                pem_data = f.read()

        if not pem_data:
            for item in self:
                certificate_file_path = item.certificate_path()
                with contextlib.suppress(FileNotFoundError), open(certificate_file_path, 'rb') as f:
                    pem_data = f.read()
                break
            else:
                return

        if not pem_data:
            return

        match = re.match(br'.*(-----BEGIN DH PARAMETERS-----.*-----END DH PARAMETERS-----)', pem_data, re.DOTALL)
        dhparam_pem = (match.group(1) + b'\n') if match else None
        match = re.match(br'.*(-----BEGIN EC PARAMETERS-----.*-----END EC PARAMETERS-----)', pem_data, re.DOTALL)
        ecparam_pem = (match.group(1) + b'\n') if match else None
        if dhparam_pem and not check_dhparam(dhparam_pem):
            dhparam_pem = None
        self._dhparams = dhparam_pem

        if ecparam_pem and not check_ecparam(ecparam_pem):
            ecparam_pem = None
        self._ecparams = ecparam_pem
