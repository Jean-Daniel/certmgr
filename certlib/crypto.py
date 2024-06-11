import abc
import hashlib
import re
import subprocess
from datetime import datetime
from io import BytesIO
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Type, TypeVar, Union

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat

from .logging import log

C = TypeVar('C', bound=ec.EllipticCurve, covariant=True)

__supported_curves = None


def _supported_curves() -> Dict[str, Type[C]]:
    global __supported_curves
    if __supported_curves is None:
        __supported_curves = {cls.name: cls for _, cls in ec.__dict__.items() if isinstance(cls, type) and cls is not ec.EllipticCurve and issubclass(cls, ec.EllipticCurve)}
    return __supported_curves


class PrivateKey(metaclass=abc.ABCMeta):

    def __init__(self, key: Union[rsa.RSAPrivateKeyWithSerialization, ec.EllipticCurvePrivateKeyWithSerialization], encrypted: bool = False):
        self._key = key
        self.encrypted = encrypted

    @property
    def key(self):
        return self._key

    @property
    @abc.abstractmethod
    def key_type(self) -> str:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def params(self) -> Union[int, str]:
        raise NotImplementedError()

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def public_key_digest(self, digest='sha256'):
        return hashlib.new(digest, self.public_key_bytes()).digest()

    def match_certificate(self, certificate: 'Certificate'):
        return self.public_key_bytes() == certificate.public_key_bytes()

    def encode(self, password: Union[str, bytes] = None):
        cipher = serialization.NoEncryption()
        if password:
            if isinstance(password, str):
                password = password.encode("utf-8")
            cipher = serialization.BestAvailableEncryption(password)
        return self._key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=cipher)

    def create_csr(self, common_name: str, alt_names: Iterable[str] = (), must_staple=False) -> x509.CertificateSigningRequest:
        subject = [
            # letencrypt ignores all other fields.
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)
        ]
        req = x509.CertificateSigningRequestBuilder(x509.Name(subject))
        if alt_names:
            req = req.add_extension(x509.SubjectAlternativeName(general_names=(x509.DNSName(name) for name in alt_names)), critical=True)

        if must_staple:
            req = req.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
        return req.sign(self._key, hashes.SHA256(), default_backend())

    @staticmethod
    def create(key_type: str, params: Union[int, str]) -> 'PrivateKey':
        if 'rsa' == key_type:
            assert isinstance(params, int)
            return _RSAKey(rsa.generate_private_key(65537, params, default_backend()))
        if 'ecdsa' == key_type:
            assert isinstance(params, str)
            curve = _supported_curves().get(params)
            if not curve:
                raise NotImplementedError('Unsupported key curve: ' + params)
            return _ECDSAKey(ec.generate_private_key(curve, default_backend()))
        raise NotImplementedError('Unsupported key type ' + key_type.upper())

    @staticmethod
    def load(key_file: str, password: Union[str, bytes, Callable] = None) -> Optional['PrivateKey']:
        try:
            with open(key_file, 'rb') as f:
                key_pem = f.read()
        except FileNotFoundError:
            return None
        # load_pem raise an error if we pass a password to a non encrypted key.
        # Moreover we don't want to prompt the user for a password if not needed.
        # So we have to detect if a password is needed.
        pwd = None
        if b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in key_pem:
            pwd = password() if callable(password) else password
            if isinstance(pwd, str):
                pwd = pwd.encode('utf-8')

        key = serialization.load_pem_private_key(key_pem, pwd, default_backend())
        return PrivateKey.from_key(key, pwd is not None)

    @staticmethod
    def from_key(key: Union[rsa.RSAPrivateKeyWithSerialization, ec.EllipticCurvePrivateKeyWithSerialization], encrypted: bool = False) -> 'PrivateKey':
        if isinstance(key, rsa.RSAPrivateKey):
            assert isinstance(key, rsa.RSAPrivateKeyWithSerialization)
            return _RSAKey(key, encrypted)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            assert isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization)
            return _ECDSAKey(key, encrypted)
        raise NotImplementedError("Unsupported key type: " + str(key.__class__))


class _RSAKey(PrivateKey):

    @property
    def key_type(self) -> str:
        return 'rsa'

    @property
    def params(self) -> int:
        return self._key.key_size

    def __str__(self):
        return f'{self.params} bits'


class _ECDSAKey(PrivateKey):

    @property
    def key_type(self) -> str:
        return 'ecdsa'

    @property
    def params(self) -> str:
        return self._key.curve.name

    def __str__(self):
        return f'curve {self.params}'


# -------- Certificates
class Certificate:

    def __init__(self, cert: x509.Certificate):
        self._cert = cert

    def __hash__(self):
        return self._cert.__hash__()

    def __eq__(self, other):
        if not isinstance(other, Certificate):
            return False

        if self is other or self._cert is other._cert:
            return True

        return self._cert == other._cert

    def encode(self, pem=True) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM if pem else serialization.Encoding.DER)

    # to test if certificate and private key match
    def public_key_bytes(self) -> bytes:
        return self._cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @property
    def serial_number(self) -> int:
        return self._cert.serial_number

    @property
    def not_before(self) -> datetime:
        return self._cert.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        return self._cert.not_valid_after_utc

    @property
    def common_name(self) -> str:
        return self._cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    @property
    def issuer_common_name(self) -> Optional[str]:
        attr = self._cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attr[0].value if attr else None

    @property
    def x509_certificate(self) -> x509.Certificate:
        return self._cert

    E = TypeVar('E', bound=x509.ExtensionType, covariant=True)

    def _extension(self, cls: Type[E]) -> Optional[E]:
        try:
            return self._cert.extensions.get_extension_for_class(cls).value
        except x509.ExtensionNotFound:
            return None

    @property
    def alt_names(self) -> Iterable[str]:
        ext = self._extension(x509.SubjectAlternativeName)
        if ext:
            return [v for v in ext.get_values_for_type(x509.DNSName)]
        return []

    @property
    def ocsp_urls(self):
        ext = self._extension(x509.AuthorityInformationAccess)
        if ext:
            return [
                access.access_location.value for access in ext if access.access_method == x509.AuthorityInformationAccessOID.OCSP
            ]
        return None

    @property
    def has_oscp_must_staple(self) -> bool:
        ext = self._extension(x509.TLSFeature)
        if ext:
            return any(feature == x509.TLSFeatureType.status_request for feature in ext)
        return False

    @staticmethod
    def load(cert_file: str) -> Optional['Certificate']:
        try:
            with open(cert_file, 'rb') as f:
                return Certificate(x509.load_pem_x509_certificate(f.read(), default_backend()))
        except FileNotFoundError:
            return None

    def dump(self, stream: BytesIO, chain: 'CertificateChain' = None, dhparam_pem: bytes = None, ecparam_pem: bytes = None,
             root_certificate: 'Certificate' = None):
        # Header
        stream.write(self.common_name.encode("utf-8"))
        stream.write(b' issued at ')
        stream.write(self.not_before.strftime('%Y-%m-%d %H:%M:%S UTC').encode("utf-8"))
        stream.write(b'\n')

        stream.write(self.encode())

        if chain:
            save_chain(stream, chain, b'\n')

        if root_certificate:
            stream.write(b'\n')
            stream.write(root_certificate.common_name.encode("utf-8"))
            stream.write(b'\n')
            stream.write(root_certificate.encode())

        if dhparam_pem:
            stream.write(b'\n')
            stream.write(dhparam_pem)

        if ecparam_pem:
            stream.write(b'\n')
            stream.write(ecparam_pem)


CertificateChain = List[Certificate]


def load_chain(chain_pem: bytes) -> CertificateChain:
    chain = []
    certificate_pems = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', chain_pem, re.DOTALL)
    for certificate_pem in certificate_pems:
        chain.append(Certificate(x509.load_pem_x509_certificate(certificate_pem, default_backend())))
    return chain


def load_chain_file(chain_file: str) -> Optional[CertificateChain]:
    try:
        with open(chain_file, 'rb') as f:
            return load_chain(f.read())
    except FileNotFoundError:
        return None


def _load_full_chain(full_chain: List[Certificate]) -> Tuple[Optional[Certificate], Optional[CertificateChain]]:
    if not full_chain:
        return None, None
    if len(full_chain) < 2:
        log.raise_error("full chain must contains at least 2 certificates")
    return full_chain[0], full_chain[1:]


def load_full_chain(chain_pem: bytes) -> Tuple[Optional[Certificate], Optional[CertificateChain]]:
    return _load_full_chain(load_chain(chain_pem))


def load_full_chain_file(chain_file: str) -> Tuple[Optional[Certificate], Optional[CertificateChain]]:
    return _load_full_chain(load_chain_file(chain_file))


def save_chain(chain_file: BytesIO, chain: CertificateChain, lead_in=b''):
    for chain_certificate in chain:
        chain_file.write(lead_in)
        chain_file.write(chain_certificate.common_name.encode("utf-8"))
        chain_file.write(b'\n')
        chain_file.write(chain_certificate.encode())
        lead_in = b'\n'


def chain_has_issuer(certificate: Certificate, chain: List[Certificate], issuer_cn: str) -> bool:
    if certificate.issuer_common_name == issuer_cn:
        return True
    return any(cert.issuer_common_name == issuer_cn for cert in chain)


# ----- Params
def generate_dhparam(dhparam_size: int) -> bytes:
    assert dhparam_size > 0
    if dhparam_size > 2048:
        log.info("generating DH param larger than 2048 bit can take an insanely great amount of time (requesting %s bit param)", dhparam_size)
    log.progress('Generating %s bit Diffie-Hellman parameters', dhparam_size)
    return subprocess.check_output(['openssl', 'dhparam', str(dhparam_size)], stderr=subprocess.DEVNULL)


def generate_ecparam(ecparam_curve: str) -> bytes:
    assert ecparam_curve
    log.progress('Generating %s elliptical curve parameters', ecparam_curve)
    return subprocess.check_output(['openssl', 'ecparam', '-name', ecparam_curve], stderr=subprocess.DEVNULL)


def check_dhparam(dhparam_pem: bytes) -> bool:
    assert dhparam_pem
    openssl = subprocess.run(['openssl', 'dhparam', '-check'], input=dhparam_pem, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0 == openssl.returncode


def check_ecparam(ecparam_pem: bytes) -> bool:
    assert ecparam_pem
    openssl = subprocess.run(['openssl', 'ecparam', '-check'], input=ecparam_pem, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0 == openssl.returncode


def get_dhparam_size(dhparam_pem: bytes) -> int:
    assert dhparam_pem
    output = subprocess.check_output(['openssl', 'dhparam', '-text'], input=dhparam_pem, stderr=subprocess.DEVNULL)
    match = re.search(r'DH Parameters: \(([0-9]+) bit\)', output.decode('ascii'))
    if match:
        return int(match.group(1))
    log.raise_error("dhparam size extraction failed: %s", output.decode('ascii'))


def get_ecparam_curve(ecparam_pem: bytes) -> str:
    assert ecparam_pem
    output = subprocess.check_output(['openssl', 'ecparam', '-text'], input=ecparam_pem, stderr=subprocess.DEVNULL)
    match = re.search(r'ASN1 OID: ([^\s]+)\n', output.decode('ascii'))
    if match:
        return match.group(1)
    log.raise_error("ecparam size extraction failed: %s", output.decode('ascii'))


def fetch_dhparam(dhparam_size: int) -> Optional[bytes]:
    if dhparam_size not in (2048, 3072, 4096, 8192):
        return log.error("--fast-params only supports 2048, 3072, 4096 and 8192 bit param (and not %s)", dhparam_size)
    url = f"https://2ton.com.au/getprimes/random/dhparam/{dhparam_size}"
    try:
        log.progress('Fetching %s bit Diffie-Hellman parameters', dhparam_size)
        req = requests.get(url)
        if req.status_code == 200:
            return req.content
        if 400 <= req.status_code < 500:
            return log.error('Unable to fetch dhparam from 2ton.com.au (HTTP error: %s %s): "%s"', req.status_code, req.reason, req.content)
        else:
            return log.error('Unable to fetch dhparam from 2ton.com.au (HTTP error: %s %s)', req.status_code, req.reason)
    except requests.RequestException:
        return log.error('dhparam fetching failed', print_exc=True)
