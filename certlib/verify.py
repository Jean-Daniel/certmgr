# Verify
import socket
import time
from collections import OrderedDict
from typing import List, Optional, Tuple

import OpenSSL

from certlib.config import VerifyDef
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


def _verify_certificate_installation(item: CertificateItem, host_name: str, port_number: int, starttls: Optional[str], cipher_list,
                                     max_ocsp_verify_attempts: int, ocsp_verify_retry_delay: int):
    ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD | OpenSSL.SSL.TLSv1_2_METHOD)
    ssl_context.set_cipher_list(cipher_list)

    try:
        if host_name.startswith('*.'):
            host_name = 'wildcard-test.' + host_name[2:]
        addr_info = socket.getaddrinfo(host_name, port_number, proto=socket.IPPROTO_TCP)
    except Exception as error:
        log.error('Unable to get "%s" address: %s', host_name, str(error))
        return

    for addr in addr_info:
        host = "{} ({}:{}): ".format(host_name, ('[' + addr[4][0] + ']') if (socket.AF_INET6 == addr[0]) else addr[4][0], port_number)
        log.progress(" • Verifying host %s", host)
        with log.prefix("   - [{}:{}] ".format(host_name, item.type.upper())):
            try:
                log.debug('Connecting')
                installed_certificates, ocsp_staple = _fetch_tls_info(addr, ssl_context, host_name, starttls)
                if item.certificate.has_oscp_must_staple:
                    attempts = 1
                    while (not ocsp_staple) and (attempts < max_ocsp_verify_attempts):
                        time.sleep(ocsp_verify_retry_delay)
                        log.debug('Retry to fetch OCSP staple')
                        installed_certificates, ocsp_staple = _fetch_tls_info(addr, ssl_context, host_name, starttls)
                        attempts += 1

                installed_certificate = installed_certificates[0]
                installed_chain = _validate_chain(installed_certificates[1:])
                if item.certificate == installed_certificate:
                    log.progress('certificate present', extra={'color': 'green'})
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
                    log.debug('Verify OCSP response status')
                    ocsp_status = ocsp_staple.cert_status
                    if 'good' == ocsp_status.lower():
                        log.progress('OCSP staple status is GOOD', extra={'color': 'green'})
                    else:
                        log.error('OCSP staple has status: %s', ocsp_status.upper())
                else:
                    if item.certificate.has_oscp_must_staple:
                        log.error('Certificate has OCSP Must-Staple but no OSCP staple found')
            except Exception as error:
                log.error('Unable to connect: %s', str(error))


def verify_certificate_installation(context: CertificateContext):
    key_type_ciphers = {}
    ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD | OpenSSL.SSL.TLSv1_2_METHOD)
    ssl_sock = OpenSSL.SSL.Connection(ssl_context, socket.socket())
    all_ciphers = ssl_sock.get_cipher_list()
    for key_type in context.config.key_types:
        key_type_ciphers[key_type] = ':'.join([cipher_name for cipher_name in all_ciphers if key_type.upper() in cipher_name]).encode('ascii')

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
                _verify_certificate_installation(item, host_name, target.port, target.starttls, key_type_ciphers[item.type], verify.ocsp_max_attempts, verify.ocsp_retry_delay)
