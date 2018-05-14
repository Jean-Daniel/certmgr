import grp
import logging
import os
import pwd
import shlex
import socket
import subprocess
import tempfile
from collections import OrderedDict

import OpenSSL
from asn1crypto import ocsp as asn1_ocsp

from . import AcmeError, log
from .ocsp import ocsp_response_status


class ColorFormatter(logging.Formatter):
    _color_codes = {
        'black': 30,
        'red': 31,
        'green': 32,
        'yellow': 33,
        'blue': 34,
        'magenta': 35,
        'cyan': 36,
        'light gray': 37,
        'dark gray': 90,
        'light red': 91,
        'light green': 92,
        'light yellow': 93,
        'light blue': 94,
        'light magenta': 95,
        'light cyan': 96,
        'white': 97
    }
    _style_codes = {
        'normal': 0,
        'bold': 1,
        'bright': 1,
        'dim': 2,
        'underline': 4,
        'underlined': 4,
        'blink': 5,
        'reverse': 7,
        'invert': 7,
        'hidden': 8
    }

    def format(self, record: logging.LogRecord):
        style = 'normal'
        if hasattr(record, 'color'):
            color = record.color
        elif record.levelno >= logging.ERROR:
            color = 'red'
            style = 'bold'
        elif record.levelno >= logging.WARNING:
            color = 'yellow'
        elif record.levelno >= logging.INFO:
            color = 'dark gray'
        else:
            color = 'light gray'

        msg = super().format(record)
        return '\033[{style};{color}m{message}\033[0m'.format(color=self._color_codes[color], style=self._style_codes[style], message=msg)


def get_user_id(user_name: str) -> int:
    try:
        return pwd.getpwnam(user_name).pw_uid
    except Exception:
        return -1


def get_group_id(group_name: str) -> int:
    try:
        return grp.getgrnam(group_name).gr_gid
    except Exception:
        return -1


def get_device_id(directory: str) -> int:
    directory = os.path.abspath(directory)
    while not os.path.exists(directory):
        directory = os.path.dirname(directory)
    return os.stat(directory).st_dev


def host_in_list(host_name, haystack_host_names):
    for haystack_host_name in haystack_host_names:
        if ((host_name == haystack_host_name)
                or (haystack_host_name.startswith('*.') and ('.' in host_name) and (host_name.split('.', 1)[1] == haystack_host_name[2:]))
                or (host_name.startswith('*.') and ('.' in haystack_host_name) and (haystack_host_name.split('.', 1)[1] == host_name[2:]))):
            return haystack_host_name
    return None


# ========= File System
def makedir(dir_path: str, chmod: int = None, warn: bool = True):
    if not os.path.isdir(dir_path):
        try:
            os.makedirs(dir_path)
            if chmod:
                if chmod & 0o700:
                    chmod |= 0o100
                if chmod & 0o070:
                    chmod |= 0o010
                if chmod & 0o007:
                    chmod |= 0o001
                try:
                    os.chmod(dir_path, chmod)
                except PermissionError as error:
                    if warn:
                        logging.warning('Unable to set directory mode for %s: %s', dir_path, str(error))
        except Exception as error:
            if warn:
                logging.warning('Unable to create directory %s: %s', dir_path, str(error))


def open_file(file_path, mode='r', chmod=0o777, warn=True):
    def opener(path, flags):
        return os.open(path, flags, mode=chmod)

    if (('w' in mode) or ('a' in mode)) and isinstance(file_path, str):
        makedir(os.path.dirname(file_path), chmod=chmod, warn=warn)
    return open(file_path, mode, opener=opener)


def rename_file(old_file_path: str, new_file_path: str, chmod: int = None, owner: str = None, group: str = None, timestamp=None):
    if os.path.isfile(old_file_path):
        makedir(os.path.dirname(new_file_path), chmod)
        os.rename(old_file_path, new_file_path)
        if chmod:
            try:
                os.chmod(new_file_path, chmod)
            except PermissionError as error:
                logging.warning('Unable to set file mode for "%s": %s', new_file_path, str(error))
        if timestamp:
            try:
                os.utime(new_file_path, (timestamp, timestamp))
            except PermissionError as error:
                logging.warning('Unable to set file time for "%s": %s', new_file_path, str(error))
        if owner or group:
            try:
                os.chown(new_file_path, get_user_id(owner), get_group_id(group))
            except PermissionError as error:
                logging.warning('Unable to set file ownership for "%s" to %s:%s: %s', new_file_path, owner, group, str(error))
        return new_file_path
    return None


class FileTransaction(object):
    __slots__ = ['file', 'temp_file_path', 'file_type', 'file_path', 'chmod', 'timestamp', 'message']
    tempdir = None

    def __init__(self, file_type, file_path, chmod=None, timestamp=None, mode='w'):
        self.file_type = file_type
        self.file_path = file_path
        self.chmod = chmod
        self.timestamp = timestamp
        temp_file_descriptor, self.temp_file_path = tempfile.mkstemp(dir=FileTransaction.tempdir)
        self.file = open(temp_file_descriptor, mode)
        self.message = ''

    def __del__(self):
        if self.file:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.file:
            self.file.close()

    def write(self, data):
        self.file.write(data)


class Hooks(object):

    def __init__(self):
        self._hooks = OrderedDict()

    # Hook Management
    def add(self, hook_name: str, hooks, **kwargs):
        if not hooks:
            return

        if hook_name not in self._hooks:
            self._hooks[hook_name] = []

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
                self._hooks[hook_name].append(hook)
        except KeyError as error:
            log.warning('Invalid hook specification for %s, unknown key %s', hook_name, error)

    def call(self):
        for hook_name, hooks in self._hooks.items():
            for hook in hooks:
                try:
                    log.info('Calling hook %s: %s', hook_name, hook['args'])
                    # TODO: add support for cwd, env, …
                    log.info(subprocess.check_output(hook['args'], stderr=subprocess.STDOUT, shell=False))
                except subprocess.CalledProcessError as error:
                    log.warning('Hook %s returned error, code: %s:\n%s', hook_name, error.returncode, error.output)
                except Exception as e:
                    log.warning('Failed to call hook %s (%s): %s', hook_name, hook['args'], str(e))
        self._clear_hooks()

    def _clear_hooks(self):
        self._hooks.clear()


# Verify
def _send_starttls(ty, sock, host_name):
    sock.settimeout(30)
    ty = ty.lower()
    if 'smtp' == ty:
        logging.debug('SMTP: %s', sock.recv(4096))
        sock.send(b'ehlo acmebot.org\r\n')
        buffer = sock.recv(4096)
        logging.debug('SMTP: %s', buffer)
        if b'STARTTLS' not in buffer:
            sock.shutdown()
            sock.close()
            raise AcmeError('STARTTLS not supported on server')
        sock.send(b'starttls\r\n')
        logging.debug('SMTP: %s', sock.recv(4096))
    elif 'pop3' == ty:
        logging.debug('POP3: %s', sock.recv(4096))
        sock.send(b'STLS\r\n')
        logging.debug('POP3: %s', sock.recv(4096))
    elif 'imap' == ty:
        logging.debug('IMAP: %s', sock.recv(4096))
        sock.send(b'a001 STARTTLS\r\n')
        logging.debug('IMAP: %s', sock.recv(4096))
    elif 'ftp' == ty:
        logging.debug('FTP: %s', sock.recv(4096))
        sock.send(b'AUTH TLS\r\n')
        logging.debug('FTP: %s', sock.recv(4096))
    elif 'xmpp' == ty:
        sock.send('<stream:stream xmlns:stream="http://etherx.jabber.org/streams" '
                  'xmlns="jabber:client" to="{host}" version="1.0">\n'.format(host=host_name).encode('ascii'))
        logging.debug('XMPP: %s', sock.recv(4096), '\n')
        sock.send(b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
        logging.debug('XMPP: %s', sock.recv(4096), '\n')
    elif 'sieve' == ty:
        buffer = sock.recv(4096)
        logging.debug('SIEVE: %s', buffer)
        if b'"STARTTLS"' not in buffer:
            sock.shutdown()
            sock.close()
            raise AcmeError('STARTTLS not supported on server')
        sock.send(b'StartTls\r\n')
        logging.debug('SIEVE: %s', sock.recv(4096))
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
    logging.debug('Connected to %s, protocol %s, cipher %s, OCSP Staple %s', ssl_sock.get_servername(), ssl_sock.get_protocol_version_name(),
                  ssl_sock.get_cipher_name(), ocsp_response_status(app_data['ocsp']).upper() if (app_data['ocsp']) else 'missing')
    installed_certificates = ssl_sock.get_peer_cert_chain()

    ssl_sock.shutdown()
    ssl_sock.close()
    return installed_certificates, app_data['ocsp']


def process_running(pid_file_path):
    try:
        with open(pid_file_path) as pid_file:
            return -1 < os.getsid(int(pid_file.read()))
    except Exception:
        pass
    return False
