import json
import os
import sys
import urllib
from typing import Optional
from urllib import parse

import josepy
import pkg_resources
from acme import client, messages

from . import VERSION
from .crypto import PrivateKey
from .logging import log
from .utils import (ArchiveAndWriteOperation, ArchiveOperation, WriteOperation, commit_file_transactions, get_key_cipher)


def _user_agent():
    acmelib = pkg_resources.get_distribution('acme')
    return 'certmgr/{version} acme-python/{acme_version}'.format(version=VERSION, acme_version=acmelib.version if acmelib else "0.0.0")


class _PasswordProvider:

    def __init__(self, passphrase):
        self.key_cipher = None
        self.passphrase = passphrase

    def __call__(self, *args, **kwargs):
        self.key_cipher = get_key_cipher('acme_client', self.passphrase, True)
        return self.key_cipher.passphrase if self.key_cipher else None


def connect_client(account_dir: str, account: str, directory_url: str, passphrase, archive_dir: Optional[str]) -> client.ClientV2:
    registration = None
    registration_path = os.path.join(account_dir, 'registration.json')
    try:
        with open(registration_path) as f:
            registration = messages.RegistrationResource.json_loads(f.read())
            log.debug('Loaded registration %s', registration_path)
            acme_url = urllib.parse.urlparse(directory_url)
            reg_url = urllib.parse.urlparse(registration.uri)
            if (acme_url[0] != reg_url[0]) or (acme_url[1] != reg_url[1]):
                log.info('ACME service URL has changed, re-registering with new client key')
                registration = None
    except FileNotFoundError:
        pass

    ops = []

    client_key = None
    client_key_cipher = None
    client_key_upgrade = False
    client_key_path = os.path.join(account_dir, 'client.key')
    # ACME-ISSUE: Resetting the client key should not be necessary, but the new registration comes back empty if we use the old key
    if registration:
        pwd = _PasswordProvider(passphrase)
        client_key = PrivateKey.load(client_key_path, pwd)
        client_key_cipher = pwd.key_cipher
        if not client_key:
            # File does not exist, try to load old client file
            try:
                client_old_key_path = os.path.join(account_dir, 'client_key.json')
                with open(client_old_key_path) as f:
                    # pylint: disable=protected-access
                    client_key = PrivateKey.from_key(josepy.JWKRSA.fields_from_json(json.load(f)).key._wrapped, False)
                    client_key_upgrade = True
                log.debug('Loaded old format client key %s', client_old_key_path)
                ops.append(ArchiveOperation('resource', client_old_key_path))
            except FileNotFoundError:
                log.debug('client key file not found')
                registration = None
        else:
            log.debug('Loaded client key %s', client_key_path)

    op = None
    if client_key_upgrade or not client_key:
        if not client_key:
            log.progress('Generating client key')
            client_key = PrivateKey.create('rsa', 4096)
        if passphrase and not client_key_cipher:
            client_key_cipher = get_key_cipher('acme_client', passphrase, False)
        op = ArchiveAndWriteOperation('resource', client_key_path, mode=0o600)
    elif client_key.encrypted and not passphrase:
        log.info("client key is encrypted but config require clear text.")
        op = ArchiveAndWriteOperation('resource', client_key_path, mode=0o600)
        client_key_cipher = None
    elif not client_key.encrypted and passphrase:
        client_key_cipher = get_key_cipher('acme_client', passphrase, False)
        log.info("client key is clear text but config require encrypted.")
        op = WriteOperation(client_key_path, mode=0o600)

    if op:
        with op.file() as f:
            f.write(client_key.encode(client_key_cipher.passphrase if client_key_cipher else None))
        ops.append(op)

    try:
        net = client.ClientNetwork(josepy.JWKRSA(key=client_key.key), account=registration, user_agent=_user_agent())
        log.debug("Fetching meta from acme server '%s'", directory_url)
        directory = messages.Directory.from_json(net.get(directory_url).json())
        acme_client = client.ClientV2(directory, net)
    except Exception as e:
        log.raise_error("Can't connect to ACME service", cause=e)
        # workaround lacks of NoReturn support in linter
        assert False

    if not registration:
        log.progress('Registering client')
        try:
            reg = messages.NewRegistration.from_data(email=account)
            if "terms_of_service" in acme_client.directory.meta:
                tos = acme_client.directory.meta.terms_of_service
                if sys.stdin.isatty():
                    sys.stdout.write('ACME service has the following terms of service:\n')
                    sys.stdout.write(tos)
                    sys.stdout.write('\n')
                    answer = input('Accept? (Y/n) ')
                    if answer and not answer.lower().startswith('y'):
                        raise Exception('Terms of service rejected.')
                    log.debug('Terms of service accepted.')
                else:
                    log.debug('Terms of service auto-accepted: %s', tos)
                reg = reg.update(terms_of_service_agreed=True)

            registration = acme_client.new_account(reg)
            op = ArchiveAndWriteOperation('resource', registration_path, mode=0o600)
            with op.file(binary=False) as f:
                f.write(registration.json_dumps())
            ops.append(op)
        except Exception as e:
            log.raise_error("Can't register with ACME service", cause=e)

    if ops:
        commit_file_transactions(ops, archive_dir)

    return acme_client
