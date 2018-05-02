import tempfile
from collections import OrderedDict
from typing import Iterable, Optional, Dict, List, Tuple

import collections
import json
import os

from . import AcmeError, log
from .utils import FileTransaction, get_device_id, host_in_list

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


def _merge(section: str, dest: dict, values: dict, check: bool = True):
    if check:
        for key, value in values.items():
            if key not in dest:
                log.warning("[config] unsupported key '%s' in section '%s'", key, section)
    dest.update(values)


class VerifyTarget(object):
    __slots__ = ('port', 'hosts', 'starttls', 'key_types')

    def __init__(self, spec):
        if isinstance(spec, int):
            self.port = spec
            self.hosts = self.starttls = self.key_types = None
        else:
            assert isinstance(spec, dict)
            if 'port' not in spec:
                log.error('[config] verify missing port definition')
            self.port = spec.get('port')
            self.hosts = spec.get('hosts')
            self.starttls = spec.get('starttls')
            self.key_types = get_list(spec, 'key_types')

        if isinstance(self.port, str):
            try:
                self.port = int(self.port)
            except ValueError:
                raise AcmeError('[config] Invalid port definition "{}"', self.port)


class PrivateKeySpec(object):
    __slots__ = ('key_types', 'key_size', 'key_curve', 'key_cipher', 'key_passphrase', 'expiration_days', 'auto_rollover', 'certificates')

    def __init__(self, spec, defaults):
        self.key_size = get_int(spec, 'key_size', defaults['key_size'])
        self.key_curve = spec.get('key_curve', defaults['key_curve'])
        self.key_cipher = spec.get('key_cipher', defaults['key_cipher'])
        self.key_passphrase = spec.get('key_passphrase', defaults['key_passphrase'])
        self.expiration_days = get_int(spec, 'expiration_days', defaults['expiration_days'])
        self.auto_rollover = get_bool(spec, 'auto_rollover', defaults['auto_rollover'])
        self.certificates = {}  # type: Dict[str, 'CertificateSpec']

        self.key_types = set()
        if self.key_size:
            self.key_types.add('rsa')
        if self.key_curve:
            self.key_types.add('ecdsa')

    @property
    def key_options(self) -> List[Tuple[str, object]]:
        options = []
        if 'rsa' in self.key_types:
            options.append(('rsa', self.key_size))
        if 'ecdsa' in self.key_types:
            options.append(('ecdsa', self.key_curve))
        return options


class CertificateSpec(object):
    __slots__ = ('common_name', 'alt_names', 'zones',
                 'key_types', 'services', 'dhparam_size', 'ecparam_curve',
                 'ocsp_must_staple', 'ocsp_responder_urls', 'ct_submit_logs', 'verify', 'tlsa_records')

    def __init__(self, name, spec, key_types, defaults):
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
        self.zones = {}
        self.alt_names = []
        for zone_name, names in alt_names.items():
            hosts = _get_domain_names(zone_name, names)
            self.zones[zone_name] = hosts
            self.alt_names += hosts

        if self.common_name not in self.alt_names:
            raise AcmeError('[config] Certificate common name "{}" not listed in alt_names in certificate "{}"', self.common_name, name)

        self.key_types = spec.get('key_types', key_types)

        self.services = spec.get('services')

        self.dhparam_size = get_int(spec, 'dhparam_size', defaults['dhparam_size'])
        self.ecparam_curve = spec.get('ecparam_curve', defaults['ecparam_curve'])

        self.ocsp_must_staple = get_bool(spec, 'ocsp_must_staple', defaults['ocsp_must_staple'])
        self.ocsp_responder_urls = get_list(spec, 'ocsp_responder_urls', defaults['ocsp_responder_urls'])

        self.ct_submit_logs = get_list(spec, 'ct_submit_logs', defaults['ct_submit_logs'])
        self.verify = [VerifyTarget(verify_spec) for verify_spec in get_list(spec, 'verify', defaults['verify'])]
        self.tlsa_records = spec.get('tlsa_records', {})


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
                    raise AcmeError('[config] Error reading config file {}: {}', config_file_path, str(e)) from e
        raise AcmeError('[config] Config file "{}" not found', file_path)

    @classmethod
    def _load(cls, file_path: str) -> 'Configuration':
        cfg = cls(file_path)
        with open(cfg.path, 'rt', encoding='utf-8') as config_file:
            data = json.load(config_file, object_pairs_hook=collections.OrderedDict)
            for section, values in data.items():
                # TODO: authorizations, http_challenges, zone_update_keys
                if section == 'account':
                    _merge('account', cfg.account, values)
                elif section == 'settings':
                    if ('slave_mode' in values) and ('follower_mode' not in values):
                        values['follower_mode'] = values['slave_mode']
                        del values['slave_mode']
                    _merge('settings', cfg.settings, values)
                    cfg._validate_settings()
                elif section == 'directories':
                    _merge('directories', cfg.directories, values)
                    cfg._validate_directories()
                elif section == 'file_names':
                    _merge('file_names', cfg.file_names, values)
                elif section == 'hooks':
                    _merge('hooks', cfg.hooks, values)
                elif section == 'services':
                    _merge('services', cfg.file_names, values, check=False)
                elif section == 'ct_logs':
                    _merge('ct_logs', cfg.ct_logs, values, check=False)
                elif section == 'certificates':
                    cfg._parse_certificates(values)
                elif section == 'private_keys':
                    cfg._parse_private_keys(values)
                elif section == 'zone_update_keys':
                    cfg.zone_update_keys = values
                elif section == 'authorizations':
                    cfg._parse_authorizations(values)
                else:
                    log.warning('[config] unknown section name: "%s"', section)
            cfg._validate_keys()

        return cfg

    def __init__(self, path: str):
        self.path = os.path.realpath(path)
        self.account = {'email': None}
        self.settings = {
            'follower_mode': False,
            'log_level': 'debug',
            'color_output': True,
            'key_size': 4096,
            'key_curve': 'secp384r1',
            'key_cipher': 'blowfish',
            'key_passphrase': None,
            'dhparam_size': 2048,
            'ecparam_curve': 'secp384r1',
            'file_user': 'root',
            'file_group': 'ssl-cert',
            'ocsp_must_staple': False,
            'ocsp_responder_urls': ['http://ocsp.int-x3.letsencrypt.org'],
            'ct_submit_logs': ['google_icarus', 'google_pilot'],
            'renewal_days': 30,
            'expiration_days': 730,
            'auto_rollover': False,
            'max_dns_lookup_attempts': 30,
            'dns_lookup_delay': 10,
            'max_domains_per_order': 100,
            'max_authorization_attempts': 30,
            'authorization_delay': 10,
            'cert_poll_time': 30,
            'max_ocsp_verify_attempts': 10,
            'ocsp_verify_retry_delay': 5,
            'min_run_delay': 300,
            'max_run_delay': 3600,
            'acme_directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
            'reload_zone_command': '/etc/bind/reload-zone.sh',
            'nsupdate_command': '/usr/bin/nsupdate',
            'verify': None
        }
        self.directories = {
            'pid': '/var/run',
            'log': '/var/log/acmebot',
            'symlinks': None,
            'resource': '/var/local/acmebot',
            'private_key': '/etc/ssl/private',
            'backup_key': '/etc/ssl/private',
            'previous_key': None,
            'full_key': '/etc/ssl/private',
            'certificate': '/etc/ssl/certs',
            'full_certificate': '/etc/ssl/certs',
            'chain': '/etc/ssl/certs',
            'param': '/etc/ssl/params',
            'challenge': '/etc/ssl/challenges',
            'http_challenge': None,
            'ocsp': '/etc/ssl/ocsp/',
            'sct': '/etc/ssl/scts/{name}/{key_type}',
            'update_key': '/etc/ssl/update_keys',
            'archive': '/etc/ssl/archive',
            'temp': None
        }
        self.file_names = {
            'log': 'acmebot.log',
            'private_key': '{name}{suffix}.key',
            'backup_key': '{name}_backup{suffix}.key',
            "previous_key": "{name}_previous{suffix}.key",
            'full_key': '{name}_full{suffix}.key',
            'certificate': '{name}{suffix}.pem',
            'full_certificate': '{name}+root{suffix}.pem',
            'chain': '{name}_chain{suffix}.pem',
            'param': '{name}_param.pem',
            'challenge': '{name}',
            'ocsp': '{name}{suffix}.ocsp',
            'sct': '{ct_log_name}.sct'
        }
        self.hooks = {
            'set_dns_challenge': None,
            'clear_dns_challenge': None,
            'dns_zone_update': None,
            'set_http_challenge': None,
            'clear_http_challenge': None,
            'private_key_rollover': None,
            'private_key_installed': None,
            'backup_key_installed': None,
            'previous_key_installed': None,
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
        self.private_keys = OrderedDict()  # type: Dict[str, PrivateKeySpec]
        self.zone_update_keys = {}
        self.authorizations = {}

    def get(self, item: str, default=None):
        return self.settings.get(item, default)

    def int(self, key: str, default=0):
        return get_int(self.settings, key, default)

    def bool(self, key: str, default=False):
        return get_bool(self.settings, key, default)

    def list(self, key: str, default=()):
        return get_list(self.settings, key, default)

    def filename(self, file_type: str) -> Optional[str]:
        return self.file_names.get(file_type)

    def filepath(self, file_type, file_name, key_type=None, **kwargs) -> str:
        if self.directory(file_type) is not None:
            directory = self.directory(file_type).format(name=file_name, key_type=key_type, suffix=_KEYS_SUFFIX[key_type] if key_type else None, **kwargs)
            file_name = self.filename(file_type).format(name=file_name, key_type=key_type, suffix=_KEYS_SUFFIX[key_type] if key_type else None, **kwargs)
            return os.path.join(directory, file_name.replace('*', '_'))
        return ''

    def directory(self, file_type: str) -> Optional[str]:
        return self.directories[file_type]

    def http_challenge_directory(self, domain_name: str, zone_name: str) -> Optional[str]:
        http_challenge_directory = self.directory('http_challenge')
        if http_challenge_directory and '{' in http_challenge_directory:
            host_name = domain_name[0:-len(zone_name)].strip('.') or '.'
            http_challenge_directory = http_challenge_directory.format(fqdn=domain_name, zone=zone_name, host=host_name)
        return http_challenge_directory

    def hook(self, hook_name: str):
        return self.hooks[hook_name]

    def ct_log(self, ct_log_name):
        return self.ct_logs.get(ct_log_name)

    def service(self, service_name: str) -> Optional[str]:
        return self.services[service_name]

    def zone_key(self, zone_name: str):
        key_data = self.zone_update_keys.get(zone_name)
        if key_data:
            if isinstance(key_data, str):
                return {'file': os.path.join(self.directory('update_key'), key_data)}
            if 'file' in key_data:
                key_data = key_data.copy()
                key_data['file'] = os.path.join(self.directory('update_key'), key_data['file'])
                return key_data
        return None

    def _parse_certificates(self, certificates: dict):
        # convert bare certificate definitions to private key definitions
        for certificate_name, certificate_spec in certificates.items():
            if certificate_name not in self.private_keys:
                self.private_keys[certificate_name] = PrivateKeySpec(certificate_spec, self.settings)

            if certificate_name not in self.private_keys[certificate_name].certificates:
                self.private_keys[certificate_name].certificates[certificate_name] = CertificateSpec(
                    certificate_name, certificate_spec, self.private_keys[certificate_name].key_types, self.settings)
            else:
                raise AcmeError('[config] Certificate "{}" already configured with private key', certificate_name)

    def _parse_private_keys(self, keys: dict):
        # convert bare certificate definitions to private key definitions
        for key_name, key_spec in keys.items():
            if key_name not in self.private_keys:
                self.private_keys[key_name] = PrivateKeySpec(key_spec, self.settings)
            else:
                # FIXME: merge properties
                raise AcmeError('[config] Private Key "{}" already configured', key_name)

            for certificate_name, certificate_spec in key_spec.get('certificates', {}).items():
                if certificate_name not in self.private_keys[key_name].certificates:
                    self.private_keys[key_name].certificates[certificate_name] = CertificateSpec(
                        certificate_name, certificate_spec, self.private_keys[key_name].key_types, self.settings)
                else:
                    raise AcmeError('[config] Certificate "{}" already configured', certificate_name)

    def _validate_settings(self):
        default_verify = self.list('verify')
        if default_verify:
            self.settings['verify'] = [VerifyTarget(spec) for spec in default_verify]

    def _validate_directories(self):
        base = os.path.dirname(self.path)
        for key, dirpath in self.directories.items():
            if not dirpath:
                continue
            if not os.path.isabs(dirpath):
                dirpath = os.path.join(base, dirpath)
            self.directories[key] = os.path.realpath(dirpath)

        temp_dir = self.directories.get('temp') or tempfile.gettempdir()
        os.makedirs(temp_dir, mode=700, exist_ok=True)
        assert os.path.exists(temp_dir)

        # FIXME: properly support multi devices file transactions
        temp_device = get_device_id(temp_dir)
        safedirs = {'pid', 'log', 'symlinks', 'temp'}
        for dirname, dirpath in self.directories.items():
            if not dirpath or dirname in safedirs:
                continue
            if get_device_id(dirpath) != temp_device:
                raise AcmeError('[config] Temp directory must be on same device as "{}" directory', dirname)
        FileTransaction.tempdir = temp_dir

    def _validate_keys(self):
        for private_key_name, pk_spec in self.private_keys.items():
            key_certificates = pk_spec.certificates
            if not key_certificates:
                raise AcmeError('[config] No certificates defined for private key "{}"', private_key_name)

            certificate_key_types = set()
            for certificate_name, certificate_spec in key_certificates.items():
                overlap_hosts = certificate_spec.alt_names
                for host_name in certificate_spec.alt_names:
                    overlap_hosts = overlap_hosts[1:]
                    overlap_host_name = host_in_list(host_name, overlap_hosts)
                    if overlap_host_name:
                        raise AcmeError('[config] alt_name "{}" conflicts with "{}" in certificate "{}"', host_name, overlap_host_name, certificate_name)

                # Validate requested key types
                for ty in certificate_spec.key_types:
                    if ty not in pk_spec.key_types:
                        raise AcmeError('[config] certificate request key type "{}" but parent private key "{}" don\'t support it', ty, private_key_name)
                    certificate_key_types.add(ty)

                verify = certificate_spec.verify
                if verify:
                    for v in verify:
                        for host_name in v.hosts or ():
                            if not host_in_list(host_name, certificate_spec.alt_names):
                                raise AcmeError('[config] Verify host "{}" not specified in certificate "{}"', host_name, certificate_name)

            pk_spec.key_types = pk_spec.key_types.intersection(certificate_key_types)
            if not pk_spec.key_types:
                raise AcmeError("[config] inconsistent key_types for private key '{}'", private_key_name)

    def _parse_authorizations(self, values):
        for zone, names in values.items():
            self.authorizations[zone] = _get_domain_names(zone, names)
