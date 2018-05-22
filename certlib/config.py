import base64
import datetime
import grp
import json
import logging
import os
import pwd
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Union

import collections

from . import AcmeError
from .logging import PROGRESS, log
from .sct import SCTLog
from .utils import FileOwner, Hook

_SUPPORTED_KEY_TYPES = ('rsa', 'ecdsa')

_SUPPORTED_CURVES = ('secp256r1', 'secp384r1', 'secp521r1')


def _get_int(config: dict, key: str, default: int = 0) -> int:
    return int(config.get(key, default))


def _get_bool(config: dict, key: str, default: bool = False) -> bool:
    return bool(config.get(key, default))


def _get_list(config: dict, key: str, default: Optional[Iterable] = None) -> Iterable:
    value = config.get(key, default)
    return value if (isinstance(value, collections.Iterable) and not isinstance(value, str)) else [] if (
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


def _check(section: str, dest: dict, values: dict):
    for key, value in values.items():
        if key not in dest:
            log.warning("unsupported key '%s' in section '%s'", key, section)


def _merge(section: str, dest: dict, values: dict, check: bool = True):
    if check:
        _check(section, dest, values)
    dest.update(values)
    return dest


class VerifyTarget(object):
    __slots__ = ('port', 'hosts', 'starttls', 'key_types')

    def __init__(self, spec):
        if isinstance(spec, (int, str)):
            self.port = spec
            self.hosts = ()
            self.starttls = self.key_types = None
        else:
            assert isinstance(spec, dict), "dict expected but got " + str(spec.__class__)
            if 'port' not in spec:
                log.raise_error('missing port definition')

            for key in spec.keys():
                if key not in ('port', 'hosts', 'starttls', 'key_types'):
                    log.warning("[verify] unknown key '%s'", key)
            self.port = spec.get('port')
            self.hosts = _get_list(spec, 'hosts')
            self.starttls = spec.get('starttls')
            self.key_types = _get_list(spec, 'key_types')

        if isinstance(self.port, str):
            try:
                self.port = int(self.port)
            except ValueError:
                log.raise_error('Invalid port definition "%s"', self.port)


class PrivateKeyDef(object):
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


class CertificateDef(object):
    SUPPORTED_KEYS = set(('name', 'alt_names', 'key_types', 'services',
                          'dhparam_size', 'ecparam_curve', 'ocsp_must_staple',
                          'ocsp_responder_urls', 'ct_submit_logs', 'verify', 'file_user',
                          'file_group') + PrivateKeyDef.SUPPORTED_KEYS)

    __slots__ = ('common_name', 'private_key', 'alt_names',
                 'fileowner', 'key_types', 'services', 'dhparam_size', 'ecparam_curve',
                 'ocsp_must_staple', 'ocsp_responder_urls', 'ct_submit_logs', 'verify', 'no_link')

    def __init__(self, spec: dict, defaults, ct_logs):
        self.common_name = spec['name'].strip().lower()

        with log.prefix("[{}] ".format(self.common_name)):
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
            self.ecparam_curve = spec.get('ecparam_curve', defaults['ecparam_curve'])

            self.ocsp_must_staple = _get_bool(spec, 'ocsp_must_staple', defaults['ocsp_must_staple'])
            self.ocsp_responder_urls = _get_list(spec, 'ocsp_responder_urls', defaults['ocsp_responder_urls'])

            self.ct_submit_logs = []
            for ct_log_name in _get_list(spec, 'ct_submit_logs', defaults['ct_submit_logs']):
                ct_log = ct_logs.get(ct_log_name)
                if ct_log:
                    self.ct_submit_logs.append(SCTLog(ct_log_name, base64.b64decode(ct_log['id']), ct_log['url']))
                else:
                    log.warning("undefined ct_log '%s'", ct_log_name)

            self.verify = [VerifyTarget(verify_spec) for verify_spec in _get_list(spec, 'verify', defaults['verify'])]
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

_DEFAULT_CT_LOGS = {
    'google_pilot': {
        'url': 'https://ct.googleapis.com/pilot',
        'id': 'pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA='
    },
    'google_icarus': {
        'url': 'https://ct.googleapis.com/icarus',
        'id': 'KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg='
    },
    'google_rocketeer': {
        'url': 'https://ct.googleapis.com/rocketeer',
        'id': '7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs='
    },
    'google_skydiver': {
        'url': 'https://ct.googleapis.com/skydiver',
        'id': 'u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU='
    },
    'google_testtube': {
        'url': 'http://ct.googleapis.com/testtube',
        'id': 'sMyD5aX5fWuvfAnMKEkEhyrH6IsTLGNQt8b9JuFsbHc='
    },
    'google_argon2018': {
        'url': 'https://ct.googleapis.com/logs/argon2018',
        'id': 'pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU='
    },
    'digicert': {
        'url': 'https://ct1.digicert-ct.com/log',
        'id': 'VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0='
    },
    'symantec_ct': {
        'url': 'https://ct.ws.symantec.com',
        'id': '3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw='
    },
    'symantec_vega': {
        'url': 'https://vega.ws.symantec.com',
        'id': 'vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU='
    },
    'cnnic': {
        'url': 'https://ctserver.cnnic.cn',
        'id': 'pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg='
    },
    'cloudflare_nimbus2018': {
        'url': 'https://ct.cloudflare.com/logs/nimbus2018',
        'id': '23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q='
    }
}


class Configuration(object):

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
        with open(cfg.path, 'rt', encoding='utf-8') as config_file, log.prefix("[config] "):
            data = json.load(config_file, object_pairs_hook=collections.OrderedDict)

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
                elif section == 'http_challenges':
                    cfg._http_challenges = values
                else:
                    log.warning('unknown section name: "%s"', section)

            certificates = data.get('certificates')
            if not certificates:
                log.raise_error('section "certificates" is required and must not be empty.')
            cfg._parse_certificates(certificates, sct_logs)

        return cfg

    def __init__(self, path: str):
        self.path = os.path.realpath(path)
        self.hooks = dict(_DEFAULT_HOOKS)  # type: Dict[str, Optional[List[Hook]]]
        self.account = {'email': None, 'passphrase': None}
        self.settings = {
            'data_dir': '/etc/certmgr',
            'http_challenge_dir': None,

            'color_output': True,
            'log_level': 'info',
            'log_file': '/var/log/certmgr/certmgr.log',

            'acme_directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
            'renewal_days': 30,
            'archive_days': 30,
            'max_authorization_attempts': 30,
            'authorization_delay': 10,
            'cert_poll_time': 30,
            'max_ocsp_verify_attempts': 10,
            'ocsp_verify_retry_delay': 5,
            'min_run_delay': 300,
            'max_run_delay': 3600,

            # certificates default values
            'file_user': None,
            'file_group': None,
            'key_size': 4096,
            'key_curve': 'secp384r1',
            'key_passphrase': None,
            'dhparam_size': 2048,
            'ecparam_curve': 'secp384r1',
            'ocsp_must_staple': False,
            'ocsp_responder_urls': ['http://ocsp.int-x3.letsencrypt.org'],
            'ct_submit_logs': ['google_icarus', 'google_pilot'],
            'verify': [443],

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

        self.certificates = OrderedDict()  # type: Dict[str, CertificateDef]
        self._http_challenges = {}

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

    def http_challenge_directory(self, domain_name: str) -> Optional[str]:
        challenge_dir = self._http_challenges.get(domain_name)
        if challenge_dir:
            return challenge_dir

        http_challenge_directory = self.get('http_challenge_dir')
        if http_challenge_directory and '{' in http_challenge_directory:
            http_challenge_directory = http_challenge_directory.format(fqdn=domain_name)
        return http_challenge_directory

    def _parse_certificates(self, certificates: List[dict], sct_logs: dict):
        common_names = set()
        alt_names = {}
        for certificate_spec in certificates:
            assert isinstance(certificate_spec, dict), "'certificates' must be a list of objects"
            cert = CertificateDef(certificate_spec, self.settings, sct_logs)
            if cert.common_name in common_names:
                log.raise_error("duplicated common name in certificates definition: %s", cert.common_name)
            common_names.add(cert.common_name)

            for host_name in cert.alt_names:
                if host_name == cert.common_name:
                    continue

                if host_name in common_names:
                    log.info(
                        "alt name %s in certificate %s conflict with existing certificate. Link will not be generated",
                        host_name, cert.common_name)
                    cert.no_link.add(host_name)
                elif host_name in alt_names:
                    existing = alt_names[host_name]
                    log.info(
                        "alt name %s in certificate %s conflict with alt name in certificate %s."
                        " Link will not be generated", host_name, cert.common_name, existing.common_name)
                    existing.no_link.add(host_name)
                    cert.no_link.add(host_name)
                alt_names[host_name] = cert

            for v in cert.verify:
                for host_name in v.hosts:
                    if not _host_in_list(host_name, cert.alt_names):
                        log.raise_error('[%s] Verify host "%s" not specified', cert.common_name, host_name)

            self.certificates[cert.common_name] = cert

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
        for file in ('log_file', 'lock_file', 'data_dir', 'http_challenge_dir'):
            value = self.get(file)
            if value and not os.path.isabs(value):
                self.settings[file] = os.path.join(basedir, value)
