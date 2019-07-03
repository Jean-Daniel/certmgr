# Verify
import hashlib
import socket
import time
from collections import OrderedDict
from typing import List, Optional, Tuple

import OpenSSL
import dns
import dns.exception
import dns.rdtypes.ANY.TLSA
from dns import rdatatype
from dns.resolver import Answer

from certlib.config import VerifyTarget
from .config import VerifyDef
from .context import CertificateContext, CertificateItem
from .crypto import Certificate
from .logging import log
from .ocsp import OCSP


def _send_starttls(ty: str, sock: socket.socket, host_name: str):
    sock.settimeout(30)
    ty = ty.lower()
    if 'smtp' == ty:
        log.debug('SMTP: %s', sock.recv(4096))
        sock.send(b'ehlo certmgr.org\r\n')
        buffer = sock.recv(4096)
        log.debug('SMTP: %s', buffer)
        if b'STARTTLS' not in buffer:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            log.raise_error('STARTTLS not supported on server')
        sock.send(b'starttls\r\n')
        log.debug('SMTP: %s', sock.recv(4096))
    elif 'pop3' == ty:
        log.debug('POP3: %s', sock.recv(4096))
        sock.send(b'STLS\r\n')
        log.debug('POP3: %s', sock.recv(4096))
    elif 'imap' == ty:
        log.debug('IMAP: %s', sock.recv(4096))
        sock.send(b'a001 STARTTLS\r\n')
        log.debug('IMAP: %s', sock.recv(4096))
    elif 'ftp' == ty:
        log.debug('FTP: %s', sock.recv(4096))
        sock.send(b'AUTH TLS\r\n')
        log.debug('FTP: %s', sock.recv(4096))
    elif 'xmpp' == ty:
        sock.send('<stream:stream xmlns:stream="http://etherx.jabber.org/streams" '
                  'xmlns="jabber:client" to="{host}" version="1.0">\n'.format(host=host_name).encode('ascii'))
        log.debug('XMPP: %s', sock.recv(4096), '\n')
        sock.send(b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
        log.debug('XMPP: %s', sock.recv(4096), '\n')
    elif 'sieve' == ty:
        buffer = sock.recv(4096)
        log.debug('SIEVE: %s', buffer)
        if b'"STARTTLS"' not in buffer:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            log.raise_error('STARTTLS not supported on server')
        sock.send(b'StartTls\r\n')
        log.debug('SIEVE: %s', sock.recv(4096))
    elif 'ldap' == ty:
        log.debug('Sending LDAP StartTLS\n')
        sock.send(b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37')
        buffer = sock.recv(4096)
        if b'\x0a\x01\x00' != buffer[7:10]:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            log.raise_error('STARTTLS not supported on server')
        log.debug('LDAP: %s', buffer.hex())
    else:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        log.raise_error('Unsuppoprted STARTTLS type: %s', ty)
    sock.settimeout(None)


def _fetch_tls_info(addr, ssl_context, host_name: str, starttls: Optional[str]) -> Tuple[List[Certificate], OCSP]:
    sock = socket.socket(addr[0], socket.SOCK_STREAM)
    sock.connect(addr[4])

    if starttls:
        _send_starttls(starttls, sock, host_name)

    def _process_ocsp(conn: OpenSSL.SSL.Connection, ocsp_data, _):
        conn.set_app_data(OCSP.decode(ocsp_data) if ocsp_data else None)
        return True

    ssl_context.set_ocsp_client_callback(_process_ocsp)
    ssl_sock = OpenSSL.SSL.Connection(ssl_context, sock)
    ssl_sock.set_connect_state()
    ssl_sock.set_tlsext_host_name(host_name.encode('ascii'))
    ssl_sock.request_ocsp()
    ssl_sock.do_handshake()
    ocsp = ssl_sock.get_app_data()
    log.debug('Connected to %s, protocol %s, cipher %s, OCSP Staple %s', ssl_sock.get_servername().decode(), ssl_sock.get_protocol_version_name(),
              ssl_sock.get_cipher_name(), ocsp.cert_status.upper() if ocsp else '<missing>')
    installed_certificates = ssl_sock.get_peer_cert_chain()  # type: List[OpenSSL.crypto.X509]

    ssl_sock.shutdown()
    ssl_sock.close()
    return [Certificate(installed_certificate.to_cryptography()) for installed_certificate in installed_certificates], ocsp


def _lookup_tlsa_records(host, port, protocol='tcp') -> List[dns.rdtypes.ANY.TLSA.TLSA]:
    try:
        answers: Answer = dns.resolver.query(f'_{port}._{protocol}.{host}.', rdatatype.TLSA)
        return answers.rrset
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []


def _tlsa_record_matches(tlsa_record: dns.rdtypes.ANY.TLSA.TLSA, certificate: Certificate, chain: List[Certificate], root_certificate: Certificate):
    matches = []
    if tlsa_record.usage in (0, 2):  # match record in chain + root
        certificates = list(chain)
        certificates.append(root_certificate)

        if tlsa_record.selector == 0:
            for chain_certificate in certificates:
                matches.append(chain_certificate.encode(pem=False))
        elif tlsa_record.selector == 1:
            for chain_certificate in certificates:
                matches.append(chain_certificate.public_key_bytes())
        else:
            log.warning('ERROR: unknown selector in TLSA record %s', tlsa_record)
    elif tlsa_record.usage in (1, 3):  # match record to certifitcate
        if tlsa_record.selector == 0:
            matches.append(certificate.encode(pem=False))
        elif tlsa_record.selector == 1:
            matches.append(certificate.public_key_bytes())
        else:
            log.warning('ERROR: unknown selector in TLSA record %s', tlsa_record)
    else:
        log.warning('ERROR: unknown usage in TLSA record %s', tlsa_record)

    for match in matches:
        if tlsa_record.mtype == 0:  # entire certificate/key
            if match.hex() == tlsa_record.cert:
                return True
        elif tlsa_record.mtype == 1:  # sha256 of data
            if hashlib.sha256(match).hexdigest() == tlsa_record.cert:
                return True
        elif tlsa_record.mtype == 2:  # sha512 of data
            if hashlib.sha512(match).hexdigest() == tlsa_record.cert:
                return True
        else:
            log.warning('ERROR: unknown matching type in TLSA record %s', tlsa_record)
    return False


def _validate_chain(chain: List[Certificate]) -> List[Certificate]:
    if len(chain) == 1:
        return chain

    sanitized = OrderedDict()
    for cert in chain:
        if cert in sanitized:
            log.warning("certificate chain contains duplicated certificate")
        else:
            sanitized[cert] = True

    return list(sanitized.keys())


# Patch OpenSSL.SSL.Context until they include it natively (https://github.com/pyca/pyopenssl/issues/848)
def set_sigalgs_list(context: OpenSSL.SSL.Context, algs_list: str):
    """
    Set the list of signatures algorithms to be used in this context.

    See the OpenSSL manual for more information (e.g.
    :manpage:`SSL_CTX_set1_sigalgs_list(1)`).

    :param bytes algs_list: An OpenSSL cipher string.
    :return: None
    """
    algs_list = OpenSSL.SSL._text_to_bytes_and_warn("algs_list", algs_list)

    if not isinstance(algs_list, bytes):
        raise TypeError("cipher_list must be a byte string.")

    OpenSSL.SSL._openssl_assert(
        OpenSSL.SSL._lib.SSL_CTX_set1_sigalgs_list(context._context, algs_list) == 1
    )


# FIXME: probably may be improved, but finding documentation about it is hard
SIGNATURES = {
    'rsa': 'RSA-PSS+SHA256:RSA-PSS+SHA384',
    'ecdsa': 'ECDSA+SHA256:ECDSA+SHA384',
}


def _verify_certificate_installation(item: CertificateItem, host_name: str, target: VerifyTarget,
                                     max_ocsp_verify_attempts: int, ocsp_verify_retry_delay: int, root_certificate: Certificate):
    ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)  # FIXME: SSLv23_METHOD is deprecated, but it map to TLS in modern OpenSSL versions.
    # This is a TLS1.3 proof way to force the returned certificate type.
    # Forcing the cipher list to RSA or ECDSA ciphers is not possible with TLS1.3
    set_sigalgs_list(ssl_context, SIGNATURES[item.type])

    port_number = target.port
    try:
        if host_name.startswith('*.'):
            host_name = 'wildcard-test.' + host_name[2:]
        addr_info = socket.getaddrinfo(host_name, port_number, proto=socket.IPPROTO_TCP)
    except Exception as error:
        log.error('Unable to get "%s" address: %s', host_name, str(error))
        return

    tlsa_records = _lookup_tlsa_records(host_name, port_number, 'tcp') if target.tlsa else None

    for addr in addr_info:
        ipaddr = ('[' + addr[4][0] + ']') if (socket.AF_INET6 == addr[0]) else addr[4][0]
        host = f"{host_name} ({ipaddr}:{port_number}): "
        log.progress(" • Verifying host %s", host)
        with log.prefix(f"   - [{host_name}:{item.type.upper()}] "):
            try:
                log.debug('Connecting')
                installed_certificates, ocsp_staple = _fetch_tls_info(addr, ssl_context, host_name, target.starttls)
                if item.certificate.has_oscp_must_staple:
                    attempts = 1
                    while (not ocsp_staple) and (attempts < max_ocsp_verify_attempts):
                        time.sleep(ocsp_verify_retry_delay)
                        log.debug('retry to fetch OCSP staple')
                        installed_certificates, ocsp_staple = _fetch_tls_info(addr, ssl_context, host_name, target.starttls)
                        attempts += 1

                installed_certificate = installed_certificates[0]
                installed_chain = _validate_chain(installed_certificates[1:])
                if item.certificate == installed_certificate:
                    log.progress('certificate match', extra={'color': 'green'})
                else:
                    log.error('certificate %s mismatch', installed_certificate.common_name)
                if len(item.chain) != len(installed_chain):
                    log.error('certificate chain length mismatch, got %s intermediate(s), expected %s', len(installed_chain), len(item.chain))
                else:
                    for intermediate, installed_intermediate in zip(item.chain, installed_chain):
                        if intermediate == installed_intermediate:
                            log.progress('Intermediate certificate "%s" present', intermediate.common_name, extra={'color': 'green'})
                        else:
                            log.error('Intermediate certificate "%s" mismatch', installed_intermediate.common_name)
                if ocsp_staple:
                    log.debug('verify OCSP response status')
                    ocsp_status = ocsp_staple.cert_status
                    if 'good' == ocsp_status.lower():
                        log.progress('OCSP staple status is GOOD', extra={'color': 'green'})
                    else:
                        log.error('OCSP staple has status: %s', ocsp_status.upper())
                else:
                    if item.certificate.has_oscp_must_staple:
                        log.error('Certificate has OCSP Must-Staple but no OSCP staple found')

                if target.tlsa:
                    log.debug('verify TLSA records')
                    if tlsa_records:
                        tlsa_match = False
                        for tlsa_record in tlsa_records:
                            with log.prefix(f" * [{tlsa_record}] "):
                                if _tlsa_record_matches(tlsa_record, installed_certificate, installed_chain, root_certificate):
                                    log.progress('TLSA record matches', extra={'color': 'green'})
                                    log.debug('    %s', tlsa_record)
                                    tlsa_match = True
                                else:
                                    log.error('TLSA record does not match')
                                    log.debug('    %s', tlsa_record)
                        if not tlsa_match:
                            log.warning('ERROR: No TLSA records match certificate')
                    else:
                        log.warning('no TLSA record found on DNS')

            except Exception as error:
                log.error('Unable to connect: %s', str(error))


def verify_certificate_installation(context: CertificateContext):
    verify = context.config.verify  # type: VerifyDef
    if not verify.targets:
        return

    for item in context:  # type: CertificateItem
        certificate = item.certificate
        if not certificate:
            log.warning('certificate not found')
            continue

        chain = item.chain
        if not chain:
            log.warning('chain not found')
            continue

        for target in verify.targets:
            if target.key_types and item.type not in target.key_types:
                continue
            for host_name in target.hosts or context.domain_names:
                _verify_certificate_installation(item, host_name, target, verify.ocsp_max_attempts, verify.ocsp_retry_delay, context.root_certificate(item.type))
