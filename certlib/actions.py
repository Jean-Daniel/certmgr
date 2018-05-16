import abc
import datetime
import os
import shutil
import stat
from argparse import Namespace
from typing import Optional

import OpenSSL
import josepy
from acme import client
from cryptography.hazmat.primitives import serialization

from certlib.utils import dirmode
from .acme import handle_authorizations
from .config import Configuration, FileManager, CertificateSpec
from .context import CertificateContext
from .crypto import PrivateKey
from .logging import log
from .verify import verify_certificate_installation


class Action(metaclass=abc.ABCMeta):
    has_acme_client = True

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client: Optional[client.ClientV2]):
        self.config = config
        self.fs = fs
        self.args = args
        self.acme_client = acme_client
        assert (not self.has_acme_client) or acme_client

    @abc.abstractmethod
    def run(self, certificate: CertificateSpec):
        raise NotImplementedError()

    def finalize(self):
        pass


def _process_symlink(root: str, name: str, target: str, link: str):
    link_path = os.path.join(root, name, link)
    if os.path.exists(target):
        try:
            if os.readlink(link_path) == target:
                return
            os.remove(link_path)
        except FileNotFoundError:
            pass
        log.debug("symlink '%s' -> '%s' created", link_path, target)
        os.symlink(target, link_path)
    else:
        try:
            os.remove(link_path)
            log.debug("symlink '%s' removed", link_path)
        except FileNotFoundError:
            pass


def update_links(certificate: CertificateSpec, fs: FileManager):
    root = fs.directory('link')
    if not root:
        return

    log.info('Update symlinks')

    with log.prefix('  - '):
        # Create main target directory
        os.makedirs(os.path.join(root, certificate.common_name), mode=0o755, exist_ok=True)

        target = fs.filepath('param', certificate.name)
        _process_symlink(root, certificate.common_name, target, 'params.pem')

        for key_type in certificate.key_types:
            with log.prefix('[{}] '.format(key_type.upper())):
                # Private Keys
                target = fs.filepath('private_key', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, key_type + '.key')

                target = fs.filepath('full_key', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, 'full.' + key_type + '.key')

                # Certificate
                target = fs.filepath('certificate', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, 'cert.' + key_type + '.pem')

                target = fs.filepath('chain', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, 'chain.' + key_type + '.pem')

                target = fs.filepath('full_certificate', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, 'cert+root.' + key_type + '.pem')

                # OCSP
                target = fs.filepath('ocsp', certificate.name, key_type)
                _process_symlink(root, certificate.common_name, target, key_type + '.ocsp')

                # SCT
                for ct_log in certificate.ct_submit_logs:
                    target = fs.filepath('sct', certificate.name, key_type, ct_log_name=ct_log.name)
                    _process_symlink(root, certificate.common_name, target, ct_log.name + '.' + key_type + '.sct')

        # process directories links (alt names -> common name)
        for name in certificate.alt_names:
            if name == certificate.common_name:
                continue
            link_path = os.path.join(root, name)
            if os.path.islink(link_path):
                if os.readlink(link_path) != certificate.common_name:
                    os.remove(link_path)
                else:
                    continue
            elif os.path.isdir(link_path):
                log.debug("removing existing directory")
                shutil.rmtree(link_path)

            os.symlink(certificate.common_name, link_path)
            log.debug("symlink '%s' -> '%s' created", link_path, certificate.common_name)


class CheckAction(Action):

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client=None):
        super().__init__(config, fs, args, acme_client)
        self._owner = config.fileowner()
        self._checked = dict()

    def _check(self, file: str, mode: int):
        try:
            s = os.stat(file, follow_symlinks=False)
            if stat.S_IMODE(s.st_mode) != mode:
                log.info('file permission should be %s not %s', oct(mode), oct(stat.S_IMODE(s.st_mode)))
                os.chmod(file, mode)

            if s.st_uid != self._owner.uid or s.st_gid != self._owner.gid:
                log.info('file owner/group should be %s/%s not %s/%s', self._owner.uid, self._owner.gid, s.st_uid, s.st_gid)
                os.chown(file, self._owner.uid, self._owner.gid)
        except FileNotFoundError:
            pass

    def _check_file(self, file: str, mode: int):
        self._check(file, mode)
        # As dir path may contains variables, it can be different for each certificate item
        # so we have to test it for every files.
        dirpath = os.path.basename(file)
        existing = self._checked.get(dirpath)
        if existing is None:
            self._check(dirpath, dirmode(mode))
            self._checked[dirpath] = existing
        elif dirmode(mode) != existing:
            log.warning("directory '%s' has conflicting permissions: %s and %s", oct(existing), oct(dirmode(mode)))

    def run(self, certificate: CertificateSpec):
        log.info('Checking installed files')

        with log.prefix("  - "):
            self._check_file(self.fs.filepath('param', certificate.name), 0o640)
        for key_type in certificate.key_types:
            with log.prefix("  - [{}] ".format(key_type.upper())):
                # Private Keys
                self._check_file(self.fs.filepath('private_key', certificate.name, key_type), 0o640)
                self._check_file(self.fs.filepath('full_key', certificate.name, key_type), 0o640)

                # Certificate
                self._check_file(self.fs.filepath('certificate', certificate.name, key_type), 0o644)
                self._check_file(self.fs.filepath('chain', certificate.name, key_type), 0o644)
                self._check_file(self.fs.filepath('full_certificate', certificate.name, key_type), 0o644)

                # OCSP
                self._check_file(self.fs.filepath('ocsp', certificate.name, key_type), 0o644)

                for ct_log in certificate.ct_submit_logs:
                    self._check_file(self.fs.filepath('sct', certificate.name, key_type, ct_log_name=ct_log.name), 0o644)

        # check symlinks
        update_links(certificate, self.fs)

    def finalize(self):
        resource = self.fs.directory('resource')
        # Check global file here
        with log.prefix("  - "):
            self._check_file(os.path.join(resource, 'client_key.json'), 0o600)
            self._check_file(os.path.join(resource, 'registration.json'), 0o600)


class RevokeAction(Action):

    def run(self, certificate: CertificateSpec):
        log.info("Revoking Certificates")

        certificate_count = 0
        revoked_certificates = []
        context = CertificateContext(certificate, self.fs)
        for item in context:
            with log.prefix("  - [{}] ".format(item.type.upper())):
                cert = item.certificate
                if cert:
                    certificate_count += 1
                    try:
                        log.debug('revoking certificate')
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.encode())
                        self.acme_client.revoke(josepy.ComparableX509(x509), 0)
                        revoked_certificates.append(item)
                        log.info('certificate revoked')
                    except Exception as error:
                        log.warning('Failed to revoke certificate: %s', str(error))
                else:
                    log.warning('certificate not found')

        with log.prefix("  - "):
            archive_date = datetime.datetime.now()
            context.archive_file('param', archive_date)
            for item in revoked_certificates:
                item.archive_file('certificate', archive_date)
                item.archive_file('chain', archive_date)
                item.archive_file('full_certificate', archive_date)

                item.archive_file('private_key', archive_date)
                item.archive_file('full_key', archive_date)

                item.archive_file('oscp', archive_date)
                for ct_log in certificate.ct_submit_logs:
                    item.archive_file('sct', archive_date, ct_log_name=ct_log.name)


class AuthAction(Action):
    def run(self, certificate: CertificateSpec):
        log.info("Process Authorization")

        with log.prefix("  - "):
            context = CertificateContext(certificate, self.fs)
            # until acme provide a clean way to create an order without using a CSR, we just create a dummy CSR …
            key = PrivateKey.create('rsa', 2048)
            csr = key.create_csr(context.spec.common_name, context.spec.alt_names, context.spec.ocsp_must_staple)
            order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
            # … and remove it from the order afterward
            order.update(csr_pem=None)

            handle_authorizations(order, self.fs, self.acme_client,
                                  self.config.int('max_authorization_attempts'), self.config.int('authorization_delay'))


class VerifyAction(Action):

    def run(self, certificate: CertificateSpec):
        log.info("Verify certificates")

        context = CertificateContext(certificate, self.fs)
        verify_certificate_installation(context, self.config.int('max_ocsp_verify_attempts'), self.config.int('ocsp_verify_retry_delay'))
