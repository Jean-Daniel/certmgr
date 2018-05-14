import json
import logging
import os
import tempfile
from collections import OrderedDict
from typing import Iterable, Optional, Dict, Union, Tuple

import collections

from . import AcmeError, log, SUPPORTED_KEY_TYPES
from .utils import FileTransaction, get_device_id, host_in_list, makedir

_KEYS_SUFFIX = {
    'rsa': '.rsa',
    'ecdsa': '.ecdsa'
}


def get_int(config: dict, key: str, default: int = 0) -> int:
    return int(config.get(key, default))


def get_bool(config: dict, key: str, default: bool = False) -> bool:
    return bool(config.get(key, default))


def get_list(config: dict, key: str, default: Optional[Iterable] = None) -> Iterable:
    value = config.get(key, default)
    return value if (isinstance(value, collections.Iterable) and not isinstance(value, str)) else [] if (value is None) else [value]


def _get_domain_names(zone_name: str, host_names):
    domain_names = []
    for host_name in host_names or ():
        host_name = host_name.strip().lower()
        domain_names.append(zone_name if ('@' == host_name) else (host_name + '.' + zone_name))
    return domain_names


def _check(section: str, dest: dict, values: dict):
    for key, value in values.items():
        if key not in dest:
            log.warning("[config] unsupported key '%s' in section '%s'", key, section)


def _merge(section: str, dest: dict, values: dict, check: bool = True):
    if check:
        _check(section, dest, values)
    dest.update(values)


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
                log.error('[config] verify missing port definition')
            self.port = spec.get('port')
            self.hosts = get_list(spec, 'hosts')
            self.starttls = spec.get('starttls')
            self.key_types = get_list(spec, 'key_types')

        if isinstance(self.port, str):
            try:
                self.port = int(self.port)
            except ValueError:
                raise AcmeError('[config] Invalid port definition "{}"', self.port)


class PrivateKeySpec(object):
    __slots__ = ('types', 'size', 'curve', 'cipher', 'passphrase')

    def __init__(self, spec, defaults):
        self.size = get_int(spec, 'key_size', defaults['key_size'])
        self.curve = spec.get('key_curve', defaults['key_curve'])
        self.cipher = spec.get('key_cipher', defaults['key_cipher'])
        self.passphrase = spec.get('key_passphrase', defaults['key_passphrase'])

        self.types = set()
        if self.size:
            self.types.add('rsa')
        if self.curve:
            self.types.add('ecdsa')

    def params(self, key_type: str) -> Union[str, int]:
        if 'rsa' == key_type:
            return self.size
        if 'ecdsa' == key_type:
            return self.curve
        raise AcmeError('Unsupported key type {}', key_type)


class CertificateSpec(object):
    __slots__ = ('private_key', 'common_name', 'alt_names',
                 'key_types', 'services', 'dhparam_size', 'ecparam_curve',
                 'ocsp_must_staple', 'ocsp_responder_urls', 'ct_submit_logs', 'verify')

    def __init__(self, name, spec, defaults):
        self.private_key = PrivateKeySpec(spec, defaults)
        self.common_name = spec.get('common_name', name).strip().lower()
        alt_names = spec.get('alt_names')
        if not alt_names:
            alt_names = {self.common_name: ['@']}
        elif '@' in alt_names:
            # convert '@' zone into common_name zone
            assert self.common_name not in alt_names
            alt_names[self.common_name] = alt_names['@']
            del alt_names['@']

        # flatten alt_names
        self.alt_names = []
        for zone_name, names in alt_names.items():
            self.alt_names.extend(_get_domain_names(zone_name, names))

        if self.common_name not in self.alt_names:
            raise AcmeError('[config] Certificate common name "{}" not listed in alt_names in certificate "{}"', self.common_name, name)

        self.key_types = spec.get('key_types', self.private_key.types)
        for kt in self.key_types:
            if kt not in SUPPORTED_KEY_TYPES:
                raise AcmeError('[config] certificate {} requests unsupported key type "{}"', name, kt)
            if kt not in self.private_key.types:
                raise AcmeError('[config] certificate {} requests key type "{}" but does not provide required params', name, kt)

        self.services = spec.get('services')

        self.dhparam_size = get_int(spec, 'dhparam_size', defaults['dhparam_size'])
        self.ecparam_curve = spec.get('ecparam_curve', defaults['ecparam_curve'])

        self.ocsp_must_staple = get_bool(spec, 'ocsp_must_staple', defaults['ocsp_must_staple'])
        self.ocsp_responder_urls = get_list(spec, 'ocsp_responder_urls', defaults['ocsp_responder_urls'])

        self.ct_submit_logs = get_list(spec, 'ct_submit_logs', defaults['ct_submit_logs'])
        self.verify = [VerifyTarget(verify_spec) for verify_spec in get_list(spec, 'verify', defaults['verify'])]


class FileManager(object):
    DEFAULT_DIRECTORIES = {
        'pid': '/var/run',
        'log': '/var/log/acmebot',
        'symlinks': None,
        'resource': '/var/local/acmebot',
        'private_key': '/etc/ssl/private',
        'full_key': '/etc/ssl/private',
        'certificate': '/etc/ssl/certs',
        'full_certificate': '/etc/ssl/certs',
        'chain': '/etc/ssl/certs',
        'param': '/etc/ssl/params',
        'http_challenge': None,
        'ocsp': '/etc/ssl/ocsp/',
        'sct': '/etc/ssl/scts/{name}/{key_type}',
        'archive': '/etc/ssl/archive',
        'temp': None
    }

    DEFAULT_FILENAMES = {
        'log': 'acmebot.log',
        'private_key': '{name}{suffix}.key',
        'full_key': '{name}_full{suffix}.key',
        'certificate': '{name}{suffix}.pem',
        'full_certificate': '{name}+root{suffix}.pem',
        'chain': '{name}_chain{suffix}.pem',
        'param': '{name}_param.pem',
        'ocsp': '{name}{suffix}.ocsp',
        'sct': '{ct_log_name}.sct'
    }

    def __init__(self, base: str, directories, filenames):
        for key, dirpath in directories.items():
            if not dirpath:
                continue
            if not os.path.isabs(dirpath):
                dirpath = os.path.join(base, dirpath)
            directories[key] = os.path.realpath(dirpath)

        temp_dir = directories.get('temp') or tempfile.gettempdir()
        os.makedirs(temp_dir, mode=700, exist_ok=True)
        assert os.path.exists(temp_dir)

        # FIXME: properly support multi devices file transactions
        temp_device = get_device_id(temp_dir)
        safedirs = {'pid', 'log', 'symlinks', 'temp'}
        for dirname, dirpath in directories.items():
            if not dirpath or dirname in safedirs:
                continue
            if get_device_id(dirpath) != temp_device:
                raise AcmeError('[config] Temp directory must be on same device as "{}" directory', dirname)
        FileTransaction.tempdir = temp_dir

        self._directories = directories
        self._filenames = filenames

    def filename(self, file_type: str) -> Optional[str]:
        return self._filenames.get(file_type)

    def filepath(self, file_type, file_name, key_type=None, **kwargs) -> str:
        if self.directory(file_type) is not None:
            directory = self.directory(file_type).format(name=file_name, key_type=key_type, suffix=_KEYS_SUFFIX[key_type] if key_type else None, **kwargs)
            file_name = self.filename(file_type).format(name=file_name, key_type=key_type, suffix=_KEYS_SUFFIX[key_type] if key_type else None, **kwargs)
            return os.path.join(directory, file_name.replace('*', '_'))
        return ''

    def directory(self, file_type: str) -> Optional[str]:
        return self._directories[file_type]

    def http_challenge_directory(self, domain_name: str) -> Optional[str]:
        http_challenge_directory = self.directory('http_challenge')
        if http_challenge_directory and '{' in http_challenge_directory:
            http_challenge_directory = http_challenge_directory.format(fqdn=domain_name)
        return http_challenge_directory


def configure_logger(level: Optional[str], fs: FileManager):
    if level is not None:
        levels = {
            "normal": logging.WARNING,
            "verbose": logging.INFO,
            "debug": logging.DEBUG,
            "detail": logging.DEBUG,
        }
        if level not in levels:
            log.warning("[config] unsupported log level: %s", level)
            level = "normal"
            log.setLevel(levels[level])
        # if level is None, don't create log file
        if fs.directory('log') and fs.filename('log'):
            makedir(fs.directory('log'), 0o700)
            log_file_path = fs.filepath('log', 'acmebot')
            log.addHandler(logging.FileHandler(log_file_path, encoding='UTF-8'))


class Configuration(object):

    @classmethod
    def load(cls, file_path: str, search_paths: Iterable[str] = ()) -> Tuple['Configuration', FileManager]:
        search_paths = ('',) if (os.path.isabs(file_path)) else search_paths
        for search_path in search_paths:
            config_file_path = os.path.join(search_path, file_path)
            if os.path.isfile(config_file_path):
                try:
                    return cls._load(config_file_path)
                except AcmeError:
                    raise
                except Exception as e:
                    raise AcmeError('[config] Error reading config file {}: {}', config_file_path, str(e)) from e
        raise AcmeError('[config] Config file "{}" not found', file_path)

    @classmethod
    def _load(cls, file_path: str) -> Tuple['Configuration', FileManager]:
        cfg = cls(file_path)
        with open(cfg.path, 'rt', encoding='utf-8') as config_file:
            data = json.load(config_file, object_pairs_hook=collections.OrderedDict)

            # configure log first, so configuration loading errors are properly logged.
            values = data.get('settings')
            if values:
                level = values.get('log_level', cfg.get('log_level'))
            else:
                level = cfg.get('log_level')

            directories = FileManager.DEFAULT_DIRECTORIES
            values = data.get('directories')
            if values:
                # check later when logger ready
                _merge('directories', directories, values, check=False)

            filenames = FileManager.DEFAULT_FILENAMES
            values = data.get('file_names')
            if values:
                # check later when logger ready
                _merge('file_names', filenames, values, check=False)

            filemgr = FileManager(os.path.dirname(cfg.path), directories, filenames)
            configure_logger(level, filemgr)

            for section, values in data.items():
                # TODO: http_challenges
                if section == 'account':
                    _merge('account', cfg.account, values)
                elif section == 'settings':
                    _merge('settings', cfg.settings, values)
                elif section == 'directories':
                    # for logging purpose only
                    _check('directories', FileManager.DEFAULT_DIRECTORIES, values)
                elif section == 'file_names':
                    # for logging purpose only
                    _check('file_names', FileManager.DEFAULT_FILENAMES, values)
                elif section == 'hooks':
                    _merge('hooks', cfg.hooks, values)
                elif section == 'services':
                    _merge('services', cfg.services, values, check=False)
                elif section == 'ct_logs':
                    _merge('ct_logs', cfg.ct_logs, values, check=False)
                elif section == 'certificates':
                    cfg._parse_certificates(values)
                else:
                    log.warning('[config] unknown section name: "%s"', section)

        return cfg, filemgr

    def __init__(self, path: str):
        self.path = os.path.realpath(path)
        self.account = {'email': None}
        self.settings = {
            'mode': None,
            'log_level': 'debug',
            'color_output': True,
            'key_size': 4096,
            'key_curve': 'secp384r1',
            'key_cipher': 'blowfish',
            'key_passphrase': None,
            'dhparam_size': 2048,
            'ecparam_curve': 'secp384r1',
            'file_user': None,
            'file_group': None,
            'ocsp_must_staple': False,
            'ocsp_responder_urls': ['http://ocsp.int-x3.letsencrypt.org'],
            'ct_submit_logs': ['google_icarus', 'google_pilot'],
            'renewal_days': 30,
            'max_authorization_attempts': 30,
            'authorization_delay': 10,
            'cert_poll_time': 30,
            'max_ocsp_verify_attempts': 10,
            'ocsp_verify_retry_delay': 5,
            'min_run_delay': 300,
            'max_run_delay': 3600,
            'acme_directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
            'verify': None
        }

        self.hooks = {
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

        self.ct_logs = {
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
        self.certificates = OrderedDict()  # type: Dict[str, CertificateSpec]

    def get(self, item: str, default=None):
        return self.settings.get(item, default)

    def int(self, key: str, default=0):
        return get_int(self.settings, key, default)

    def bool(self, key: str, default=False):
        return get_bool(self.settings, key, default)

    def list(self, key: str, default=()):
        return get_list(self.settings, key, default)

    def hook(self, hook_name: str):
        return self.hooks[hook_name]

    def ct_log(self, ct_log_name):
        return self.ct_logs.get(ct_log_name)

    def service(self, service_name: str) -> Optional[str]:
        return self.services[service_name]

    def _parse_certificates(self, certificates: dict):
        host_names = set()
        for certificate_name, certificate_spec in certificates.items():
            cert = CertificateSpec(certificate_name, certificate_spec, self.settings)
            for host_name in cert.alt_names:
                if host_name in host_names:
                    log.info("[config] {} host name defined in two certificates ({} and an other one)", host_name, certificate_name)
                host_names.add(host_name)

            for v in cert.verify:
                for host_name in v.hosts:
                    if not host_in_list(host_name, cert.alt_names):
                        raise AcmeError('[config] Verify host "{}" not specified in certificate "{}"', host_name, certificate_name)

            self.certificates[certificate_name] = cert
