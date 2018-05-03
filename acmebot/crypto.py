import hashlib
import logging
import re
import subprocess
from datetime import datetime
from typing import Union

import OpenSSL
from OpenSSL.crypto import X509, PKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat


def generate_rsa_key(key_size: int):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, key_size)
    return key


def generate_ecdsa_key(key_curve: str):
    key_curve = key_curve.lower()
    if 'secp256r1' == key_curve:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif 'secp384r1' == key_curve:
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif 'secp521r1' == key_curve:
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    else:
        logging.warning('Unsupported key curve: %s', key_curve)
        return None
    #        return OpenSSL.crypto.PKey.from_cryptography_key(key)  # currently not supported
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)


def generate_csr(private_key, common_name, alt_names=(), must_staple=False):
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = common_name
    extensions = [
        OpenSSL.crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join('DNS:%s' % domain_name for domain_name in alt_names).encode('ascii')
        )
    ]
    if must_staple:
        extensions.append(ocsp_must_staple_extension())
    req.add_extensions(extensions)
    req.set_version(2)
    req.set_pubkey(private_key)
    req.sign(private_key, 'sha256')
    return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)


def generate_private_key(key_type: str, options: Union[int, str]):
    if 'rsa' == key_type:
        return generate_rsa_key(options)
    if 'ecdsa' == key_type:
        return generate_ecdsa_key(options)
    logging.warning('Unknown key type %s', key_type.upper())
    return None


def private_key_matches_options(key_type, private_key, options: Union[str, int]):
    if 'rsa' == key_type:
        return private_key.bits() == options
    if 'ecdsa' == key_type:
        return private_key.to_cryptography_key().curve.name == options
    logging.warning('Unknown key type %s', key_type.upper())
    return False


def private_key_descripton(key_type, options: Union[str, int]):
    if 'rsa' == key_type:
        return '{key_size} bits'.format(key_size=options)
    if 'ecdsa' == key_type:
        return 'curve {key_curve}'.format(key_curve=options)
    logging.warning('Unknown key type %s', key_type.upper())
    return ''


def public_key_bytes(private_key: PKey):
    if private_key:
        return private_key.to_cryptography_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return None


def certificate_public_key_bytes(certificate):
    if certificate:
        return certificate.get_pubkey().to_cryptography_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return None


def public_key_digest(private_key, digest='sha256'):
    if 'sha256' == digest:
        return hashlib.sha256(public_key_bytes(private_key)).digest()
    return hashlib.sha512(public_key_bytes(private_key)).digest()


def certificate_bytes(certificate):
    if certificate:
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, certificate)
    return None


def ocsp_must_staple_extension():
    return OpenSSL.crypto.X509Extension(b'1.3.6.1.5.5.7.1.24', critical=False, value=b'DER:30:03:02:01:05')


def get_alt_names(certificate: X509):
    for index in range(certificate.get_extension_count()):
        extension = certificate.get_extension(index)
        if b'subjectAltName' == extension.get_short_name():
            return [alt_name.split(':')[1] for alt_name in str(extension).split(', ')]
    return []


def has_oscp_must_staple(certificate: X509):
    ocsp_must_staple = ocsp_must_staple_extension()
    for index in range(certificate.get_extension_count()):
        extension = certificate.get_extension(index)
        if ((ocsp_must_staple.get_short_name() == extension.get_short_name())
                and (ocsp_must_staple.get_data() == extension.get_data())):
            return True
    return False


def private_key_matches_certificate(private_key, certificate: X509):
    return public_key_bytes(private_key) == certificate_public_key_bytes(certificate)


def certificate_digest(certificate, digest='sha256'):
    return certificate.digest(digest).decode('ascii').replace(':', '').lower()


def certificates_match(certificate1, certificate2):
    return (OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate1) ==
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate2))


def datetime_from_asn1_generaltime(general_time):
    try:
        return datetime.strptime(general_time.decode('ascii'), '%Y%m%d%H%M%SZ')
    except ValueError:
        return datetime.strptime(general_time.decode('ascii'), '%Y%m%d%H%M%S%z')


def save_chain(chain_file, chain, lead_in=''):
    for chain_certificate in chain:
        chain_certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, chain_certificate).decode('ascii')
        chain_file.write(lead_in + chain_certificate.get_subject().commonName + '\n')
        chain_file.write(chain_certificate_pem)
        lead_in = '\n'


def save_certificate(certificate_file, certificate, chain=None, root_certificate=None, dhparam_pem=None, ecparam_pem=None):
    certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate).decode('ascii')
    certificate_not_before = datetime_from_asn1_generaltime(certificate.get_notBefore())
    certificate_file.write(certificate.get_subject().commonName + ' issued at ' + certificate_not_before.strftime('%Y-%m-%d %H:%M:%S UTC') + '\n')
    certificate_file.write(certificate_pem)

    if chain:
        save_chain(certificate_file, chain, '\n')

    if root_certificate:
        root_certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, root_certificate).decode('ascii')
        certificate_file.write('\n' + root_certificate.get_subject().commonName + '\n')
        certificate_file.write(root_certificate_pem)

    if dhparam_pem:
        certificate_file.write('\n' + dhparam_pem)
        certificate_file.write('\n' + ecparam_pem)


def decode_full_chain(full_chain_pem):
    full_chain = []
    certificate_pems = re.findall('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', full_chain_pem, re.DOTALL)
    for certificate_pem in certificate_pems:
        full_chain.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_pem.encode('ascii')))
    return full_chain[0], full_chain[1:]


# ----- Params
def generate_dhparam(dhparam_size):
    if dhparam_size:
        try:
            return subprocess.check_output(['openssl', 'dhparam', str(dhparam_size)], stderr=subprocess.DEVNULL).decode('ascii')
        except Exception as e:
            logging.error("dhparam generation failed: %s", str(e))
    return None


def generate_ecparam(ecparam_curve):
    if ecparam_curve:
        try:
            return subprocess.check_output(['openssl', 'ecparam', '-name', ecparam_curve], stderr=subprocess.DEVNULL).decode('ascii')
        except Exception as e:
            logging.error("ecparam generation failed: %s", str(e))
    return None


def check_dhparam(dhparam_pem):
    if dhparam_pem:
        try:
            openssl = subprocess.Popen(['openssl', 'dhparam', '-check'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            openssl.communicate(input=dhparam_pem.encode('ascii'))
            return 0 == openssl.returncode
        except Exception as e:
            logging.error("dhparam check failed: %s", str(e))
    return False


def check_ecparam(ecparam_pem):
    if ecparam_pem:
        try:
            openssl = subprocess.Popen(['openssl', 'ecparam', '-check'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            openssl.communicate(input=ecparam_pem.encode('ascii'))
            return 0 == openssl.returncode
        except Exception as e:
            logging.error("ecparam check failed: %s", str(e))
    return False


def get_dhparam_size(dhparam_pem):
    if dhparam_pem:
        try:
            output = subprocess.check_output(['openssl', 'dhparam', '-text'], input=dhparam_pem.encode('ascii'), stderr=subprocess.DEVNULL)
            match = re.match(r'\s*(?:PKCS#3)?\s*DH Parameters: \(([0-9]+) bit\)\n', output.decode('ascii'))
            if match:
                return int(match.group(1))
        except Exception as e:
            logging.error("dhparam size reading failed: %s", str(e))
    return 0


def get_ecparam_curve(ecparam_pem):
    if ecparam_pem:
        try:
            output = subprocess.check_output(['openssl', 'ecparam', '-text'], input=ecparam_pem.encode('ascii'), stderr=subprocess.DEVNULL)
            match = re.match(r'ASN1 OID: ([^\s]+)\n', output.decode('ascii'))
            if match:
                return match.group(1)
        except Exception as e:
            logging.error("ecparam curve reading failed: %s", str(e))
    return None
