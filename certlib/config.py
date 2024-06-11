import base64
import binascii
import datetime
import grp
import json
import logging
import os
import pwd
from enum import Enum
from typing import Container, Dict, Iterable, List, Optional, Tuple, Union

import yaml

from . import AcmeError
from .logging import PROGRESS, log
from .sct import SCTLog, SCTLogEntry
from .utils import FileOwner, Hook

_SUPPORTED_KEY_TYPES = ('rsa', 'ecdsa')

_SUPPORTED_CURVES = ('secp256r1', 'secp384r1', 'secp521r1')


def _get_int(config: dict, key: str, default: int = 0) -> int:
    return int(config.get(key, default))


def _get_bool(config: dict, key: str, default: bool = False) -> bool:
    return bool(config.get(key, default))


def _get_list(config: dict, key: str, default: Optional[Iterable] = None) -> Iterable:
    value = config.get(key, default)
    return value if (isinstance(value, Iterable) and not isinstance(value, str)) else [] if (
            value is None) else [value]


def _host_in_list(host_name, haystack_host_names):
    for haystack_host_name in haystack_host_names:
        if host_name == haystack_host_name:
            return haystack_host_name
        if haystack_host_name.startswith('*.') and ('.' in host_name) and (
                host_name.split('.', 1)[1] == haystack_host_name[2:]):
            return haystack_host_name
        if host_name.startswith('*.') and ('.' in haystack_host_name) and (
                haystack_host_name.split('.', 1)[1] == host_name[2:]):
            return haystack_host_name
    return None


def _check(section: str, expected: Container[str], values: dict):
    for key, value in values.items():
        if key not in expected:
            log.warning("unsupported key '%s' in section '%s'", key, section)


def _merge(section: str, dest: dict, values: dict, check: bool = True):
    if check:
        _check(section, dest, values)
    dest.update(values)
    return dest


class VerifyTarget:
    __slots__ = ('port', 'hosts', 'starttls', 'tlsa', 'key_types')

    def __init__(self, spec):
        if isinstance(spec, (int, str)):
            self.port = spec
            self.hosts = ()
            self.tlsa = False
            self.starttls = self.key_types = None
        else:
            assert isinstance(spec, dict), "dict expected but got " + str(spec.__class__)
            if 'port' not in spec:
                log.raise_error('missing port definition')

            for key in spec.keys():
                if key not in ('port', 'hosts', 'starttls', 'tlsa', 'key_types'):
                    log.warning("[verify] unknown key '%s'", key)
            self.port = spec.get('port')
            self.hosts = _get_list(spec, 'hosts')
            self.tlsa = spec.get('tlsa')
            self.starttls = spec.get('starttls')
            self.key_types = _get_list(spec, 'key_types')

        if isinstance(self.port, str):
            try:
                self.port = int(self.port)
            except ValueError:
                log.raise_error('Invalid port definition "%s"', self.port)


class VerifyDef:
    __slots__ = ('targets', 'ocsp_max_attempts', 'ocsp_retry_delay')

    def __init__(self, spec, defaults: 'VerifyDef' = None):
        self.ocsp_max_attempts: int = defaults.ocsp_max_attempts if defaults else 10
        self.ocsp_retry_delay: int = defaults.ocsp_retry_delay if defaults else 5
        if isinstance(spec, list):
            self.targets = [VerifyTarget(verify_spec) for verify_spec in spec]
        elif spec:
            _check("verify", {'targets', 'ocsp_max_attempts', 'ocsp_retry_delay'}, spec)
            self.targets = [VerifyTarget(verify_spec) for verify_spec in _get_list(spec, 'targets')]
            self.ocsp_max_attempts = _get_int(spec, 'ocsp_max_attempts', self.ocsp_max_attempts)
            self.ocsp_retry_delay = _get_int(spec, 'ocsp_retry_delay', self.ocsp_retry_delay)
        else:
            self.targets = []


class AuthType(Enum):
    noop = 0
    dns = 1
    http = 2
    hook = 3


class AuthDef:
    type: AuthType

    @staticmethod
    def parse(spec, default=None) -> 'AuthDef':
        if not spec:
            return NoAuthDef()
        ty = spec.pop('type', None)
        if not ty:
            log.raise_error('auth: key type is required')
        if ty == 'noop':
            return NoAuthDef()
        if ty == 'http':
            return HttpAuthDef(spec, default if default and default.type == 'http' else None)
        if ty == 'dns':
            return DnsAuthDef(spec, default if default and default.type == 'dns' else None)
        if ty == 'hook':
            return HookAuthDef(spec, default if default and default.type == 'hook' else None)
        log.raise_error('auth: key type must be one of "noop", "http", "dns", or "hook".')


class NoAuthDef(AuthDef):
    type = AuthType.noop


class HttpAuthDef(AuthDef):
    type = AuthType.http

    def __init__(self, spec, default=Optional['HttpAuthDef']):
        super().__init__()
        _check("auth:http", {'challenge_dir', 'delay', 'retry'}, spec)
        challenge_dir = spec.get('challenge_dir', None)

        # noinspection PyProtectedMember
        self._challenge_dirs = dict(default._challenge_dirs) if default else {}
        if isinstance(challenge_dir, dict):
            # noinspection PyProtectedMember
            self._default_dir = challenge_dir.pop('default', default._default_dir if default else None)
            self._challenge_dirs.update(challenge_dir)
        else:
            self._default_dir = challenge_dir

        self.delay: int = _get_int(spec, 'delay', default.delay if default else 10)
        self.retry: int = _get_int(spec, 'retry', default.retry if default else 30)

    def challenge_directory(self, domain: str) -> Optional[str]:
        challenge_dir = self._challenge_dirs.get(domain)
        if challenge_dir:
            return challenge_dir

        http_challenge_directory = self._default_dir
        if http_challenge_directory and '{fqdn' in http_challenge_directory:
            http_challenge_directory = http_challenge_directory.format(fqdn=domain)
        return http_challenge_directory


class TsigKey:
    __slots__ = ('id', 'secret', 'algorithm')

    SUPPORTED_AGORITHMS = {
        "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"
    }

    def __init__(self, spec):
        _check("auth:dns:key", {'id', 'secret', 'algorithm'}, spec)
        self.id: str = spec.get('id', None)
        self.secret: str = spec.get('secret', None)
        if not self.id or not self.secret:
            log.raise_error("Missing required value for 'id' or 'secret' in TSIG Key")
        self.algorithm: str = spec.get('algorithm', 'hmac-sha256')
        if self.algorithm not in self.SUPPORTED_AGORITHMS:
            log.raise_error('Unsupported TSIG algorithm: "%s". Must be one of %s', self.algorithm, sorted(self.SUPPORTED_AGORITHMS))


class DnsAuthDef(AuthDef):
    type = AuthType.dns

    def __init__(self, spec, default=Optional['DnsAuthDef']):
        super().__init__()
        _check("auth:dns", {'key', 'zone', 'server', 'delay', 'retry'}, spec)

        zone = spec.get('zone', None)
        # noinspection PyProtectedMember
        self._zones = dict(default._zones) if default else {}
        if isinstance(zone, dict):
            # noinspection PyProtectedMember
            self._default_zone = zone.pop('default', default._default_zone if default else None)
            self._zones.update(zone)
        else:
            self._default_zone = zone

        # ditto for servers
        server = spec.get('server', None)
        # noinspection PyProtectedMember
        self._servers = dict(default._servers) if default else {}
        if isinstance(server, dict) and 'host' not in server:
            # noinspection PyProtectedMember
            self._default_server = server.pop('default', default._default_server if default else None)
            self._servers.update(server)
        else:
            self._default_server = server

        # ditto for keys
        key = spec.get('key', None)
        # noinspection PyProtectedMember
        self._keys = dict(default._keys) if default else {}
        if key is not None and 'secret' not in key:
            default_key = server.pop('key', None)
            if default_key:
                self._default_key = TsigKey(default_key)
            else:
                # noinspection PyProtectedMember
                self._default_key = default._default_key if default else None
            self._keys.update({domain: TsigKey(k) for domain, k in key.items()})
        else:
            self._default_key = TsigKey(key) if key else None

        self.delay: int = _get_int(spec, 'delay', default.delay if default else 10)
        self.retry: int = _get_int(spec, 'retry', default.retry if default else 30)

    def key(self, domain: str) -> Optional[TsigKey]:
        key = self._keys.get(domain)
        return key or self._default_key

    def server(self, domain: str) -> Optional[Tuple[str, int]]:
        server = self._servers.get(domain) or self._default_server
        if isinstance(server, dict):
            return server.get('host'), server.get('port', 53)

        return (server, 53) if server else None

    def zone(self, domain: str) -> str:
        zone = self._zones.get(domain)
        if zone:
            return zone

        if self._default_zone:
            return self._default_zone

        # FIXME: default to assuming all zones are simple zones (name.tld)
        # should use public suffix list instead
        components = domain.rsplit('.', 2)
        if len(components) <= 2:
            return domain
        return '.'.join(components[-2:])


class HookAuthDef(AuthDef):
    type = AuthType.hook

    def __init__(self, spec, default=Optional['HookAuthDef']):
        super().__init__()
        cmd = spec.get('command')
        if not cmd:
            log.raise_error('auth: hook auth requires a command.')
        self.cmd = Hook('auth', cmd)
        # each_domain: if true, call hook for each domain that needs auth
        #              if false, call it once per csr with the csr common name as parameter
        self.each_domain: bool = spec.get('each_domain', default.each_domain if default else False)


class PrivateKeyDef:
    __slots__ = ('types', 'size', 'curve', 'passphrase')

    SUPPORTED_KEYS = ('key_size', 'key_curve', 'key_passphrase')

    def __init__(self, spec, defaults):
        self.size = _get_int(spec, 'key_size', defaults['key_size'])
        if self.size < 0:
            log.raise_error("key_size must be an integer >= 0: %s", self.size)

        self.curve = spec.get('key_curve', defaults['key_curve'])
        if self.curve and self.curve not in _SUPPORTED_CURVES:
            log.raise_error("key_curve must be null or one of %s: %s", _SUPPORTED_CURVES, self.curve)

        self.passphrase = spec.get('key_passphrase', defaults['key_passphrase'])
        self.types = []
        if self.size:
            self.types.append('rsa')
        if self.curve:
            self.types.append('ecdsa')

    def params(self, key_type: str) -> Union[str, int]:
        if 'rsa' == key_type:
            return self.size
        if 'ecdsa' == key_type:
            return self.curve
        log.raise_error('Unsupported key type %s', key_type)


class CertificateDef:
    SUPPORTED_KEYS = set(('name', 'alt_names', 'key_types', 'services', 'preferred_chain',
                          'dhparam_size', 'fast_dhparam', 'ecparam_curve', 'ocsp_must_staple',
                          'ocsp_responder_urls', 'ct_submit_logs', 'file_user', 'file_group', 'auth', 'verify') + PrivateKeyDef.SUPPORTED_KEYS)

    __slots__ = ('common_name', 'private_key', 'alt_names', 'fileowner', 'key_types',
                 'services', 'preferred_chain', 'dhparam_size', 'fast_dhparam', 'ecparam_curve',
                 'ocsp_must_staple', 'ocsp_responder_urls', 'ct_submit_logs', 'auth', 'verify', 'no_link')

    def __init__(self, spec: dict, defaults, auth: Optional[AuthDef], verify: Optional[VerifyDef], ct_logs):
        self.common_name = spec['name'].strip().lower()

        with log.prefix(f"[{self.common_name}] "):
            for key in spec.keys():
                if key not in self.SUPPORTED_KEYS:
                    log.warning("unknown parameter %s", key)

            self.private_key = PrivateKeyDef(spec, defaults)
            self.alt_names = [self.common_name if domain == '@' else domain for domain in _get_list(spec, 'alt_names')]
            if self.common_name not in self.alt_names:
                self.alt_names.insert(0, self.common_name)

            self.key_types = spec.get('key_types', self.private_key.types)  # type: Iterable[str]
            for kt in self.key_types:
                if kt not in _SUPPORTED_KEY_TYPES:
                    log.raise_error('unsupported key type "%s"', kt)
                if kt not in self.private_key.types:
                    log.raise_error('requests key type "%s" but does not provide required params', kt)

            self.services = spec.get('services')

            self.dhparam_size = _get_int(spec, 'dhparam_size', defaults['dhparam_size'])
            self.fast_dhparam = _get_bool(spec, 'fast_dhparam', defaults['fast_dhparam'])
            self.ecparam_curve = spec.get('ecparam_curve', defaults['ecparam_curve'])

            self.ocsp_must_staple = _get_bool(spec, 'ocsp_must_staple', defaults['ocsp_must_staple'])
            self.ocsp_responder_urls = _get_list(spec, 'ocsp_responder_urls', defaults['ocsp_responder_urls'])

            self.preferred_chain = spec.get('preferred_chain', defaults['preferred_chain'])

            self.ct_submit_logs = []
            for ct_log_name in _get_list(spec, 'ct_submit_logs', defaults['ct_submit_logs']):
                ct_log = ct_logs.get(ct_log_name)
                if ct_log:
                    if not isinstance(ct_log, list):
                        ct_log = [ct_log]

                    entries = []
                    for ct_log_entry in ct_log:
                        start = datetime.datetime.fromisoformat(ct_log_entry.get('start', '2000-01-01T00:00:00Z').replace('Z', '+00:00'))
                        end = datetime.datetime.fromisoformat(ct_log_entry.get('start', '2999-01-01T00:00:00Z').replace('Z', '+00:00'))
                        entry = SCTLogEntry(ct_log_entry['url'],
                                            base64.b64decode(ct_log_entry['log_id']),
                                            base64.b64decode(ct_log_entry['key']),
                                            start, end)
                        entries.append(entry)

                    self.ct_submit_logs.append(SCTLog(ct_log_name, entries))
                else:
                    log.warning("undefined ct_log '%s'", ct_log_name)

            if 'auth' in spec:
                self.auth = AuthDef.parse(spec.get('auth'), auth)
            else:
                self.auth = auth
            self.verify = VerifyDef(spec.get('verify'), verify)
            self.no_link = set()

            # Compute file owner
            try:
                selfuid = os.getuid()
                user = spec.get('file_user', defaults['file_user'])
                uid = pwd.getpwnam(user).pw_uid if user else selfuid

                selfgid = os.getgid()
                group = spec.get('file_group', defaults['file_group'])
                gid = grp.getgrnam(group).gr_gid if group else selfgid

                self.fileowner = FileOwner(uid, gid, uid == selfuid and gid == selfgid)
            except Exception as e:
                log.raise_error("Failed to determine user and group ID", cause=e)

    @property
    def name(self):
        return self.common_name


def configure_logger(log_file: str, level: Optional[str]):
    if level is None:
        level = "quiet"

    levels = {
        "quiet": logging.WARNING,
        "normal": PROGRESS,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }
    if level not in levels:
        log.warning("unsupported log level: %s", level)
        level = "normal"
    log.set_file(log_file, levels[level])
    log.info('\n----- certmgr executed at %s', str(datetime.datetime.now()), extra={'prefix': ''})


_DEFAULT_HOOKS = {
    'set_http_challenge': None,
    'clear_http_challenge': None,
    'private_key_installed': None,
    'certificate_installed': None,
    'full_certificate_installed': None,
    'chain_installed': None,
    'full_key_installed': None,
    'params_installed': None,
    'sct_installed': None,
    'ocsp_installed': None,
    'certificates_updated': None
}


def _hex_to_base64(hexstr: str) -> str:
    return base64.b64encode(binascii.unhexlify(hexstr.replace(':', ''))).decode('ascii')


_DEFAULT_CT_LOGS = {
    'google_argon': [
        {
            'log_id': '6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==',
            'url': 'https://ct.googleapis.com/logs/argon2023/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': '7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==',
            'url': 'https://ct.googleapis.com/logs/us1/argon2024/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': 'TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==',
            'url': 'https://ct.googleapis.com/logs/us1/argon2025h1/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2025-07-01T00:00:00Z',
        },
        {
            'log_id': 'EvFONL1TckyEBhnDjz96E/jntWKHiJxtMAWE6+WGJjo=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+TzlCzfpie1/rJhgxnIITojqKk9VK+8MZoc08HjtsLzD8e5yjsdeWVhIiWCVk6Y6KomKTYeKGBv6xVu93zQug==',
            'url': 'https://ct.googleapis.com/logs/us1/argon2025h2/',
            'start': '2025-07-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'google_xenon': [
        {
            'log_id': 'rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEchY+C+/vzj5g3ZXLY3q5qY1Kb2zcYYCmRV4vg6yU84WI0KV00HuO/8XuQqLwLZPjwtCymeLhQunSxgAnaXSuzg==',
            'url': 'https://ct.googleapis.com/logs/xenon2023/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': 'dv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQ=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==',
            'url': 'https://ct.googleapis.com/logs/eu1/xenon2024/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': 'zxFW7tUufK/zh1vZaS6b6RpxZ0qwF+ysAdJbd87MOwg=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEguLOkEA/gQ7f6uEgK14uMFRGgblY7a+9/zanngtfamuRpcGY4fLN6xcgcMoqEuZUeFDc/239HKe2Oh/5JqkbvQ==',
            'url': 'https://ct.googleapis.com/logs/eu1/xenon2025h1/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2025-07-01T00:00:00Z',
        },
        {
            'log_id': '3dzKNJXX4RYF55Uy+sef+D0cUN/bADoUEnYKLKy7yCo=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa+Cv7QZ8Pe/ZDuRYSwTYKkeZkIl6uTaldcgEuMviqiu1aJ2IKaKlz84rmhWboD6dlByyt0ryUexA7WJHpANJhg==',
            'url': 'https://ct.googleapis.com/logs/eu1/xenon2025h2/',
            'start': '2025-07-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'cloudflare_nimbus': [
        {
            'log_id': 'ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA==',
            'url': 'https://ct.cloudflare.com/logs/nimbus2023/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': '2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==',
            'url': 'https://ct.cloudflare.com/logs/nimbus2024/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': 'zPsPaoVxCWX+lZtTzumyfCLphVwNl422qX5UwP5MDbA=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGoAaFRkZI3m0+qB5jo3VwdzCtZaSfpTgw34UfAoNLUaonRuxQWUMX5jEWhd5gVtKFEHsr6ldDqsSGXHNQ++7lw==',
            'url': 'https://ct.cloudflare.com/logs/nimbus2025/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'digicert_log_server': {
        'log_id': 'VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=',
        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==',
        'url': 'https://ct1.digicert-ct.com/log/',
    },
    'digicert_log_server_2': {
        'log_id': 'h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=',
        'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==',
        'url': 'https://ct2.digicert-ct.com/log/',
    },
    'digicert_yeti': [
        {
            'log_id': 'Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQ0DsdWYitzwFTvG3F4Nbj8Nv5XIVYzQpkyWsU4nuSYlmcwrAp6m092fsdXEw6w1BAeHlzaqrSgNfyvZaJ9y0Q==',
            'url': 'https://yeti2023.ct.digicert.com/log/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': 'SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHM=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV7jBbzCkfy7k8NDZYGITleN6405Tw7O4c4XBGA0jDliE0njvm7MeLBrewY+BGxlEWLcAd2AgGnLYgt6unrHGSw==',
            'url': 'https://yeti2024.ct.digicert.com/log/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': 'fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebg=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35UAXhDBAfc34xB00f+yypDtMplfDDn+odETEazRs3OTIMITPEy1elKGhj3jlSR82JGYSDvw8N8h8bCBWlklQw==',
            'url': 'https://yeti2025.ct.digicert.com/log/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'digicert_nessie': [
        {
            'log_id': 's3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXu8iQwSCRSf2CbITGpUpBtFVt8+I0IU0d1C36Lfe1+fbwdaI0Z5FktfM2fBoI1bXBd18k2ggKGYGgdZBgLKTg==',
            'url': 'https://nessie2023.ct.digicert.com/log/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': 'c9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQesF3crU=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELfyieza/VpHp/j/oPfzDp+BhUuos6QWjnycXgQVwa4FhRIr4OxCAQu0DLwBQIfxBVISjVNUusnoWSyofK2YEKw==',
            'url': 'https://nessie2024.ct.digicert.com/log/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': '5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlA=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vDwp4uBLgk5O59C2jhEX7TM7Ta72EN/FklXhwR/pQE09+hoP7d4H2BmLWeadYC3U6eF1byrRwZV27XfiKFvOA==',
            'url': 'https://nessie2025.ct.digicert.com/log/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'sectigo_sabre': [
        {
            'log_id': 'VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==',
            'url': 'https://sabre.ct.comodo.com/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': 'ouK/1h7eLy8HoNZObTen3GVDsMa1LqLat4r4mm31F9g=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELAH2zjG8qhRhUf5reoeuptObx4ctClrIT7VU3MmToADuyhy5p7Z7RzvlT6psFhxwLsjsU1pMIUx+JwsTFF78hQ==',
            'url': 'https://sabre2024h1.ct.sectigo.com/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2024-07-01T00:00:00Z',
        },
        {
            'log_id': 'GZgQcQnw1lIuMIDSnj9ku4NuKMz5D1KO7t/OSj8WtMo=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEehBMiucie20quo76a0qB1YWuA+//S/xNUz23jLt1CcnqFn7BdxbSwkV0bY3E4Yg339TzYGX8oHXwIGaOSswZ2g==',
            'url': 'https://sabre2024h2.ct.sectigo.com/',
            'start': '2024-07-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': '4JKz/AwdyOdoNh/eYbmWTQpSeBmKctZyxLBNpW1vVAQ=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfi858egjjrMyBK9NV/bbxXSkem07B1EMWvuAMAXGWgzEdtYGqFdN+9/kgpDCQa5wszGi4/o9XyxdBM20nVWrQQ==',
            'url': 'https://sabre2025h1.ct.sectigo.com/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2025-07-01T00:00:00Z',
        },
        {
            'log_id': 'GgT/SdBUHUCv9qDDv/HYxGcvTuzuI0BomGsXQC7ciX0=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhRMRLXvzk4HkuXzZZDvntYOZZnlZR2pCXta9Yy63kUuuvFbExW4JoNdkGsjBr4mL9VjYuut7g1Lp9OClzc2SzA==',
            'url': 'https://sabre2025h2.ct.sectigo.com/',
            'start': '2025-07-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'sectigo_mammoth': [
        {
            'log_id': 'b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==',
            'url': 'https://mammoth.ct.comodo.com/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-01T00:00:00Z',
        },
        {
            'log_id': 'KdA6G7Z0qnEc0wNbZVfBT4qni0/oOJRJ7KRT+US9JGg=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpFmQ83EkJPfDVSdWnKNZHve3n86rThlmTdCK+p1ipCTwOyDkHRRnyPzkN/JLOFRaz59rB5DQDn49TIey6D8HzA==',
            'url': 'https://mammoth2024h1.ct.sectigo.com/',
            'start': '2024-01-01T00:00:00Z',
            'end': '2024-07-01T00:00:00Z',
        },
        {
            'log_id': '3+FW66oFr7WcD4ZxjajAMk6uVtlup/WlagHRwTu+Ulw=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhWYiJG6+UmIKoK/DJRo2LqdgiaJlv6RfvYVqlAWBNZBUMZXnEZ6jLg+F76eIV4tjGoHBQZ197AE627nBJ/RlHg==',
            'url': 'https://mammoth2024h2.ct.sectigo.com/',
            'start': '2024-07-01T00:00:00Z',
            'end': '2025-01-01T00:00:00Z',
        },
        {
            'log_id': 'E0rfGrWYQgl4DG/vTHqRpBa3I0nOWFdq367ap8Kr4CI=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEzxBtTB9LkqhqGvSxVdrmP5+79Uh4rpdsLqFEW6U4D2ojm1WjUQCnrCDzFTfm05yYks8DDLdhvvrPmbNd1hb5Q==',
            'url': 'https://mammoth2025h1.ct.sectigo.com/',
            'start': '2025-01-01T00:00:00Z',
            'end': '2025-07-01T00:00:00Z',
        },
        {
            'log_id': 'rxgaKNaMo+CpikycZ6sJ+Lu8IrquvLE4o6Gd0/m2Aw0=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiOLHs9c3o5HXs8XaB1EEK4HtwkQ7daDmZeFKuhuxnKkqhDEprh2L8TOfEi6QsRVnZqB8C1tif2yaajCbaAIWbw==',
            'url': 'https://mammoth2025h2.ct.sectigo.com/',
            'start': '2025-07-01T00:00:00Z',
            'end': '2026-01-01T00:00:00Z',
        },
    ],
    'lets_encrypt_oak': [
        {
            'log_id': _hex_to_base64('B7:3E:FB:24:DF:9C:4D:BA:75:F2:39:C5:BA:58:F4:6C:5D:FC:42:CF:7A:9F:35:C4:9E:1D:09:81:25:ED:B4:99'),
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsz0OeL7jrVxEXJu+o4QWQYLKyokXHiPOOKVUL3/TNFFquVzDSer7kZ3gijxzBp98ZTgRgMSaWgCmZ8OD74mFUQ==',
            'url': 'https://oak.ct.letsencrypt.org/2023/',
            'start': '2023-01-01T00:00:00Z',
            'end': '2024-01-07T00:00:00Z',
        },
        {
            'log_id': _hex_to_base64('3B:53:77:75:3E:2D:B9:80:4E:8B:30:5B:06:FE:40:3B:67:D8:4F:C3:F4:C7:BD:00:0D:2D:72:6F:E1:FA:D4:17'),
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVkPXfnvUcre6qVG9NpO36bWSD+pet0Wjkv3JpTyArBog7yUvuOEg96g6LgeN5uuk4n0kY59Gv5RzUo2Wrqkm/Q==',
            'url': 'https://oak.ct.letsencrypt.org/2024h1/',
            'start': '2023-12-20T00:00:00Z',
            'end': '2024-07-20T00:00:00Z',
        },
        {
            'log_id': _hex_to_base64('3F:17:4B:4F:D7:22:47:58:94:1D:65:1C:84:BE:0D:12:ED:90:37:7F:1F:85:6A:EB:C1:BF:28:85:EC:F8:64:6E'),
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13PWU0fp88nVfBbC1o9wZfryUTapE4Av7fmU01qL6E8zz8PTidRfWmaJuiAfccvKu5+f81wtHqOBWa+Ss20waA==',
            'url': 'https://oak.ct.letsencrypt.org/2024h2/',
            'start': '2024-06-20T00:00:00Z',
            'end': '2025-01-20T00:00:00Z',
        },
        {
            'log_id': 'ouMK5EXvva2bfjjtR2d3U9eCW4SU1yteGyzEuVCkR+c=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKeBpU9ejnCaIZeX39EsdF5vDvf8ELTHdLPxikl4y4EiROIQfS4ercpnMHfh8+TxYVFs3ELGr2IP7hPGVPy4vHA==',
            'url': 'https://oak.ct.letsencrypt.org/2025h1/',
            'start': '2024-12-20T00:00:00Z',
            'end': '2025-07-20T00:00:00Z',
        },
        {
            'log_id': 'DeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQ=',
            'key': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtXYwB63GyNLkS9L1vqKNnP10+jrW+lldthxg090fY4eG40Xg1RvANWqrJ5GVydc9u8H3cYZp9LNfkAmqrr2NqQ==',
            'url': 'https://oak.ct.letsencrypt.org/2025h2/',
            'start': '2025-06-20T00:00:00Z',
            'end': '2026-01-20T00:00:00Z',
        },
    ],
}


class Configuration:

    @classmethod
    def load(cls, file_path: str, search_paths: Iterable[str] = ()) -> 'Configuration':
        search_paths = ('',) if (os.path.isabs(file_path)) else search_paths
        for search_path in search_paths:
            config_file_path = os.path.join(search_path, file_path)
            if os.path.isfile(config_file_path):
                try:
                    return cls._load(config_file_path)
                except AcmeError:
                    raise
                except Exception as e:
                    log.raise_error('Error reading config file %s: %s', config_file_path, str(e), cause=e)
        raise AcmeError('Config file "{}" not found', file_path)

    @classmethod
    def _load(cls, file_path: str) -> 'Configuration':
        cfg = cls(file_path)
        with open(cfg.path, 'rb') as config_file, log.prefix("[config] "):
            if cfg.path.endswith("json"):
                data = json.load(config_file)
            else:
                data = yaml.load(config_file)

            # configure log first, so configuration loading errors are properly logged.
            values = data.get('settings')
            if values:
                level = values.get('log_level', cfg.get('log_level'))
                log_file = values.get('log_file', cfg.get('log_file'))
            else:
                level = cfg.get('log_level')
                log_file = cfg.get('log_file')

            if log_file:
                configure_logger(os.path.join(os.path.dirname(cfg.path), log_file), level)

            sct_logs = dict(_DEFAULT_CT_LOGS)
            for section, values in data.items():
                if section == 'account':
                    _merge('account', cfg.account, values)
                elif section == 'settings':
                    cfg._merge_settings(values)
                elif section == 'hooks':
                    _check('hooks', _DEFAULT_HOOKS, values)
                    cfg._parse_hooks(values)
                elif section == 'services':
                    _merge('services', cfg.services, values, check=False)
                elif section == 'ct_logs':
                    _merge('ct_logs', sct_logs, values, check=False)
                elif section == 'certificates':
                    pass
                else:
                    log.warning('unknown section name: "%s"', section)
            # merging done -> parse auth spec
            cfg.auth = AuthDef.parse(cfg.settings['auth'])

            verify = VerifyDef(cfg.settings['verify'])
            certificates = data.get('certificates')
            if not certificates:
                log.raise_error('section "certificates" is required and must not be empty.')
            cfg._parse_certificates(certificates, verify, sct_logs)

        return cfg

    def __init__(self, path: str):
        self.path = os.path.realpath(path)
        self.hooks = dict(_DEFAULT_HOOKS)  # type: Dict[str, Optional[List[Hook]]]
        self.account = {'email': None, 'passphrase': None}
        self.settings = {
            'data_dir': '/etc/certmgr',

            'auth': None,
            'color_output': True,
            'log_level': 'info',
            'log_file': '/var/log/certmgr/certmgr.log',

            'acme_directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
            'renewal_days': 30,
            'archive_days': 30,
            'cert_poll_time': 30,
            # running with random wait time
            'min_run_delay': 300,
            'max_run_delay': 3600,

            # certificates default values
            'file_user': None,
            'file_group': None,
            'key_size': 4096,
            'key_curve': 'secp384r1',
            'key_passphrase': None,
            'dhparam_size': 2048,
            'fast_dhparam': True,  # Using 2ton.com.au online generator to get dhparam instead of generating them locally
            'ecparam_curve': 'secp384r1',
            'ocsp_must_staple': False,
            'ocsp_responder_urls': ['http://ocsp.int-x3.letsencrypt.org'],
            'ct_submit_logs': ['google_argon', 'google_xenon'],
            'preferred_chain': None,  # "DST Root CA X3"
            'verify': {
                'targets': [443],
                'ocsp_max_attempts': 10,
                'ocsp_retry_delay': 5,
            },

            'lock_file': '/var/run/lock/certmgr.lock',
        }
        self.services = {
            'apache': 'systemctl reload apache2',
            'coturn': 'systemctl restart coturn',
            'dovecot': 'systemctl restart dovecot',
            'etherpad': 'systemctl restart etherpad',
            'mysql': 'systemctl reload mysql',
            'nginx': 'systemctl reload nginx',
            'postfix': 'systemctl reload postfix',
            'postgresql': 'systemctl reload postgresql',
            'prosody': 'systemctl restart prosody',
            'slapd': 'systemctl restart slapd',
            'synapse': 'systemctl restart matrix-synapse',
            'znc': 'systemctl restart znc'
        }

        # _load() must init it
        # noinspection PyTypeChecker
        self.auth = None  # type: AuthDef
        self._certificates = {}  # type: Dict[str, CertificateDef]

    def get(self, item: str, default=None):
        return self.settings.get(item, default)

    def int(self, key: str, default=0):
        return _get_int(self.settings, key, default)

    def bool(self, key: str, default=False):
        return _get_bool(self.settings, key, default)

    def list(self, key: str, default=()):
        return _get_list(self.settings, key, default)

    def service(self, service_name: str) -> Optional[str]:
        return self.services[service_name]

    def certificate(self, name: str) -> List[CertificateDef]:
        cert = self._certificates.get(name)
        if cert:
            return [cert]

        aliases = []
        for cert in self._certificates.values():
            if name in cert.alt_names:
                aliases.append(cert)
        return aliases

    def certificate_names(self) -> Iterable[str]:
        return self._certificates.keys()

    @property
    def data_dir(self) -> str:
        return self.settings['data_dir']

    @property
    def account_dir(self) -> str:
        return os.path.join(self.data_dir, 'account')

    def archive_dir(self, name: str) -> Optional[str]:
        if self.int('archive_days') <= 0:
            return None

        archive = os.path.join(self.data_dir, 'archives')
        date = datetime.datetime.now().strftime('%Y_%m_%d_%H%M%S')
        return os.path.join(archive, name, date)

    def _parse_certificates(self, certificates: List[dict], verify: Optional[VerifyDef], sct_logs: dict):
        common_names = set()
        alt_names = {}
        for certificate_spec in certificates:
            assert isinstance(certificate_spec, dict), "'certificates' must be a list of objects"
            cert = CertificateDef(certificate_spec, self.settings, self.auth, verify, sct_logs)
            if cert.common_name in common_names:
                log.raise_error("duplicated common name in certificates definition: %s", cert.common_name)
            common_names.add(cert.common_name)

            for host_name in cert.alt_names:
                if host_name == cert.common_name:
                    continue

                if host_name in common_names:
                    log.info(
                        "alt name %s in certificate %s conflicts with existing certificate. Link will not be generated",
                        host_name, cert.common_name)
                    cert.no_link.add(host_name)
                elif host_name in alt_names:
                    existing = alt_names[host_name]
                    log.info(
                        "alt name %s in certificate %s conflicts with alt name in certificate %s."
                        " Link will not be generated", host_name, cert.common_name, existing.common_name)
                    existing.no_link.add(host_name)
                    cert.no_link.add(host_name)
                alt_names[host_name] = cert

            for v in cert.verify.targets:
                for host_name in v.hosts:
                    if not _host_in_list(host_name, cert.alt_names):
                        log.raise_error('[%s] Verify host "%s" not specified', cert.common_name, host_name)

            self._certificates[cert.common_name] = cert

    def _parse_hooks(self, values: dict):
        for name, spec in values.items():
            if not spec:
                continue
            if isinstance(spec, list):
                hooks = [Hook(name, item) for item in spec]
            else:
                hooks = [Hook(name, spec)]

            self.hooks[name] = hooks

    def _merge_settings(self, values):
        _merge('settings', self.settings, values)
        basedir = os.path.dirname(self.path)
        for file in ('log_file', 'lock_file', 'data_dir'):
            value = self.get(file)
            if value and not os.path.isabs(value):
                self.settings[file] = os.path.join(basedir, value)
