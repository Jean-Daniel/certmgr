# Verify
import socket

import OpenSSL
from asn1crypto import ocsp as asn1_ocsp

from . import log, AcmeError
from .ocsp import ocsp_response_status


def _send_starttls(ty, sock, host_name):
    sock.settimeout(30)
    ty = ty.lower()
    if 'smtp' == ty:
        log.debug('SMTP: %s', sock.recv(4096))
        sock.send(b'ehlo acmebot.org\r\n')
        buffer = sock.recv(4096)
        log.debug('SMTP: %s', buffer)
        if b'STARTTLS' not in buffer:
            sock.shutdown()
            sock.close()
            raise AcmeError('STARTTLS not supported on server')
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
            sock.shutdown()
            sock.close()
            raise AcmeError('STARTTLS not supported on server')
        sock.send(b'StartTls\r\n')
        log.debug('SIEVE: %s', sock.recv(4096))
    else:
        sock.shutdown()
        sock.close()
        raise Exception('Unsuppoprted STARTTLS type: ' + ty)
    sock.settimeout(None)


def fetch_tls_info(addr, ssl_context, key_type, host_name, starttls):
    sock = socket.socket(addr[0], socket.SOCK_STREAM)
    sock.connect(addr[4])

    if starttls:
        _send_starttls(starttls, sock, host_name)

    def _process_ocsp(conn, ocsp_data, data):
        conn.get_app_data()['ocsp'] = asn1_ocsp.OCSPResponse.load(ocsp_data) if (b'' != ocsp_data) else None
        return True

    app_data = {'has_ocsp': False}
    ssl_context.set_ocsp_client_callback(_process_ocsp)
    ssl_sock = OpenSSL.SSL.Connection(ssl_context, sock)
    ssl_sock.set_app_data(app_data)
    ssl_sock.set_connect_state()
    ssl_sock.set_tlsext_host_name(host_name.encode('ascii'))
    ssl_sock.request_ocsp()
    ssl_sock.do_handshake()
    log.debug('Connected to %s, protocol %s, cipher %s, OCSP Staple %s', ssl_sock.get_servername(), ssl_sock.get_protocol_version_name(),
              ssl_sock.get_cipher_name(), ocsp_response_status(app_data['ocsp']).upper() if (app_data['ocsp']) else 'missing')
    installed_certificates = ssl_sock.get_peer_cert_chain()

    ssl_sock.shutdown()
    ssl_sock.close()
    return installed_certificates, app_data['ocsp']

# def _verify_certificate_installation(self, certificate_name, certificate, chain, key_type, host_name, port_number, starttls, cipher_list):
#     ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
#     ssl_context.set_cipher_list(cipher_list)
#
#     try:
#         if host_name.startswith('*.'):
#             host_name = 'wildcard-test.' + host_name[2:]
#         addr_info = socket.getaddrinfo(host_name, port_number, proto=socket.IPPROTO_TCP)
#     except Exception as error:
#         log.warning('ERROR: Unable to get address for %s: %s', host_name, str(error))
#         return
#
#     for addr in addr_info:
#         host_desc = host_name + ' at ' + (('[' + addr[4][0] + ']') if (socket.AF_INET6 == addr[0]) else addr[4][0]) + ':' + str(port_number)
#         try:
#             log.debug('Connecting to %s with %s ciphers', host_desc, key_type.upper())
#             installed_certificates, ocsp_staple = fetch_tls_info(addr, ssl_context, key_type, host_name, starttls)
#             if has_oscp_must_staple(certificate):
#                 attempts = 1
#                 while (not ocsp_staple) and (attempts < self.config.int('max_ocsp_verify_attempts')):
#                     time.sleep(self.config.int('ocsp_verify_retry_delay'))
#                     log.debug('Retrying to fetch OCSP staple')
#                     installed_certificates, ocsp_staple = fetch_tls_info(addr, ssl_context, key_type, host_name, starttls)
#                     attempts += 1
#
#             installed_certificate = installed_certificates[0]
#             installed_chain = installed_certificates[1:]
#             if certificates_match(certificate, installed_certificate):
#                 log.info('%s certificate %s present on %s', key_type.upper(), certificate_name, host_desc, extra={'color': 'green'})
#             else:
#                 log.warning('ERROR: %s certificate "%s" mismatch on %s', key_type.upper(), installed_certificate.get_subject().commonName, host_desc)
#             if len(chain) != len(installed_chain):
#                 log.warning('ERROR: %s certificate chain length mismatch on %s, got %s intermediate(s), expected %s', key_type.upper(), host_desc,
#                             len(installed_chain), len(chain))
#             else:
#                 for intermediate, installed_intermediate in zip(chain, installed_chain):
#                     if certificates_match(intermediate, installed_intermediate):
#                         log.info('Intermediate %s certificate "%s" present on %s', key_type.upper(), intermediate.get_subject().commonName, host_desc,
#                                  extra={'color': 'green'})
#                     else:
#                         log.warning('ERROR: Intermediate %s certificate "%s" mismatch on %s', key_type.upper(),
#                                     installed_intermediate.get_subject().commonName, host_desc)
#             if ocsp_staple:
#                 ocsp_status = ocsp_response_status(ocsp_staple)
#                 if 'good' == ocsp_status.lower():
#                     log.info('OCSP staple status is GOOD on %s', host_desc, extra={'color': 'green'})
#                 else:
#                     log.warning('ERROR: OCSP staple has status: %s on %s', ocsp_status.upper(), host_desc)
#             else:
#                 if has_oscp_must_staple(certificate):
#                     log.warning('ERROR: Certificate has OCSP Must-Staple but no OSCP staple found on %s')
#
#         except Exception as error:
#             log.warning('ERROR: Unable to connect to %s via %s: %s', host_desc, key_type.upper(), str(error))
#
# def verify_certificate_installation(self, certificate_names):
#     key_type_ciphers = {}
#     ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
#     ssl_sock = OpenSSL.SSL.Connection(ssl_context, socket.socket())
#     all_ciphers = ssl_sock.get_cipher_list()
#     for key_type in SUPPORTED_KEY_TYPES:
#         key_type_ciphers[key_type] = ':'.join([cipher_name for cipher_name in all_ciphers if key_type.upper() in cipher_name]).encode('ascii')
#
#     for certificate_name, cert_spec in self.config.certificates.items():
#         if certificate_names and (certificate_name not in certificate_names):
#             continue
#
#         verify_list = cert_spec.verify
#         if not verify_list:
#             continue
#
#         keys = []
#         key_cipher_data = self.key_cipher_data(certificate_name)
#         try:
#             for key_type in cert_spec.key_types:
#                 keys.append((key_type, self.load_private_key(certificate_name, key_type, key_cipher_data)))
#         except PrivateKeyError as error:
#             log.warning('Unable to load private key %s: %s', certificate_name, str(error))
#             continue
#
#         for key_type in cert_spec.key_types:
#             certificate = self.load_certificate(certificate_name, key_type)
#             if not certificate:
#                 log.warning('%s certificate %s not found', key_type.upper(), certificate_name)
#                 continue
#
#             chain = self.load_chain(certificate_name, key_type)
#
#             for verify in verify_list:
#                 if verify.key_types and key_type not in verify.key_types:
#                     continue
#                 for host_name in verify.hosts or cert_spec.alt_names:
#                     self._verify_certificate_installation(certificate_name, certificate, chain, key_type,
#                                                           host_name, verify.port, verify.starttls, key_type_ciphers[key_type])
