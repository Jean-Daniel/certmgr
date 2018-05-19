import abc
import contextlib
import os
import shutil
import stat
from argparse import Namespace
from typing import Optional

import OpenSSL
import josepy
from acme import client
from cryptography.hazmat.primitives import serialization

from certlib.utils import FileOwner
from .acme import handle_authorizations
from .config import Configuration, FileManager
from .context import CertificateContext
from .context import CertificateItem
from .crypto import PrivateKey
from .logging import log
from .utils import ArchiveOperation, Hooks, commit_file_transactions, dirmode
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
    def run(self, context: CertificateContext):
        raise NotImplementedError()

    def finalize(self):
        pass


def _process_symlink(root: str, name: str, target: str, link: str):
    link_path = os.path.join(root, name, link)
    if os.path.exists(target):
        with contextlib.suppress(FileNotFoundError):
            if os.readlink(link_path) == target:
                return
            os.remove(link_path)
        log.debug("symlink '%s' -> '%s' created", link_path, target)
        os.symlink(target, link_path)
    else:
        with contextlib.suppress(FileNotFoundError):
            os.remove(link_path)
            log.debug("symlink '%s' removed", link_path)


def update_links(context: CertificateContext):
    root = context.fs.directory('link')
    if not root:
        return

    log.info('Update symlinks')

    with log.prefix('  - '):
        # Create main target directory
        os.makedirs(os.path.join(root, context.common_name), mode=0o755, exist_ok=True)

        target = context.filepath('param')
        _process_symlink(root, context.common_name, target, 'params.pem')

        for item in context:
            with log.prefix('[{}] '.format(item.type.upper())):
                # Private Keys
                target = item.filepath('private_key')
                _process_symlink(root, context.common_name, target, item.type + '.key')

                target = item.filepath('full_key')
                _process_symlink(root, context.common_name, target, 'full.' + item.type + '.key')

                # Certificate
                target = item.filepath('certificate')
                _process_symlink(root, context.common_name, target, 'cert.' + item.type + '.pem')

                target = item.filepath('chain')
                _process_symlink(root, context.common_name, target, 'chain.' + item.type + '.pem')

                target = item.filepath('full_certificate')
                _process_symlink(root, context.common_name, target, 'cert+root.' + item.type + '.pem')

                # OCSP
                target = item.filepath('ocsp')
                _process_symlink(root, context.common_name, target, item.type + '.ocsp')

                # SCT
                for ct_log in context.config.ct_submit_logs:
                    target = item.filepath('sct', ct_log_name=ct_log.name)
                    _process_symlink(root, context.common_name, target, ct_log.name + '.' + item.type + '.sct')

        # process directories links (alt names -> common name)
        for name in context.domain_names:
            if name == context.common_name:
                continue
            link_path = os.path.join(root, name)
            if os.path.islink(link_path):
                if os.readlink(link_path) != context.common_name:
                    os.remove(link_path)
                else:
                    continue
            elif os.path.isdir(link_path):
                log.debug("removing existing directory")
                shutil.rmtree(link_path)

            os.symlink(context.common_name, link_path)
            log.debug("symlink '%s' -> '%s' created", link_path, context.common_name)


class CheckAction(Action):
    has_acme_client = False

    def __init__(self, config: Configuration, fs: FileManager, args: Namespace, acme_client=None):
        super().__init__(config, fs, args, acme_client)
        self._checked = dict()

    @staticmethod
    def _check(file: str, mode: int, owner: FileOwner):
        with contextlib.suppress(FileNotFoundError):
            s = os.stat(file, follow_symlinks=False)
            if stat.S_IMODE(s.st_mode) != mode:
                log.info('file permission should be %s not %s', oct(mode), oct(stat.S_IMODE(s.st_mode)))
                os.chmod(file, mode)

            if s.st_uid != owner.uid or s.st_gid != owner.gid:
                log.info('file "%s" owner/group should be %s/%s not %s/%s', file, owner.uid, owner.gid, s.st_uid, s.st_gid)
                os.chown(file, owner.uid, owner.gid)

    def _check_file(self, file: str, mode: int, owner: FileOwner):
        self._check(file, mode, owner)
        # As dir path may contains variables, it can be different for each certificate item
        # so we have to test it for every files.
        dirpath = os.path.basename(file)
        existing = self._checked.get(dirpath)
        if existing is None:
            self._check(dirpath, dirmode(mode), owner)
            self._checked[dirpath] = existing
        elif dirmode(mode) != existing:
            log.warning("directory '%s' has conflicting permissions: %s and %s", oct(existing), oct(dirmode(mode)))

    def run(self, context: CertificateContext):
        log.info('Checking installed files')

        owner = context.config.fileowner
        with log.prefix("  - "):
            self._check_file(context.filepath('param'), 0o640, owner)
        for item in context:
            with log.prefix("  - [{}] ".format(item.type.upper())):
                # Private Keys
                self._check_file(item.filepath('private_key'), 0o640, owner)
                self._check_file(item.filepath('full_key'), 0o640, owner)

                # Certificate
                self._check_file(item.filepath('certificate'), 0o644, owner)
                self._check_file(item.filepath('chain'), 0o644, owner)
                self._check_file(item.filepath('full_certificate'), 0o644, owner)

                # OCSP
                self._check_file(item.filepath('ocsp'), 0o644, owner)

                for ct_log in context.config.ct_submit_logs:
                    self._check_file(item.filepath('sct', ct_log_name=ct_log.name), 0o644, owner)

        # check symlinks
        update_links(context)

    def finalize(self):
        owner = FileOwner(os.getuid(), os.getgid(), True)
        resource = self.fs.directory('resource')
        # Check global file here
        with log.prefix("  - "):
            self._check_file(os.path.join(resource, 'client.key'), 0o600, owner)
            self._check_file(os.path.join(resource, 'registration.json'), 0o600, owner)


class RevokeAction(Action):

    def run(self, context: CertificateContext):
        log.info("Revoking Certificates")

        certificate_count = 0
        revoked_certificates = []
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
            ops = [ArchiveOperation('certificates', context.filepath('param'))]
            for item in revoked_certificates:  # type: CertificateItem
                ops.append(ArchiveOperation('certificates', item.filepath('certificate')))
                ops.append(ArchiveOperation('certificates', item.filepath('chain')))
                ops.append(ArchiveOperation('certificates', item.filepath('full_certificate')))

                ops.append(ArchiveOperation('keys', item.filepath('private_key')))
                ops.append(ArchiveOperation('keys', item.filepath('full_key')))

                ops.append(ArchiveOperation('meta', item.filepath('oscp')))
                for ct_log in context.config.ct_submit_logs:
                    ops.append(ArchiveOperation('meta', item.filepath('sct', ct_log_name=ct_log.name)))
            commit_file_transactions(ops, self.fs.archive_dir(context.name))


class AuthAction(Action):
    def run(self, context: CertificateContext):
        log.info("Process Authorization")

        with log.prefix("  - "):
            # until acme provide a clean way to create an order without using a CSR, we just create a dummy CSR …
            key = PrivateKey.create('rsa', 2048)
            csr = key.create_csr(context.common_name, context.domain_names, context.config.ocsp_must_staple)
            order = self.acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
            # … and remove it from the order afterward
            order.update(csr_pem=None)

            handle_authorizations(order, self.fs, self.acme_client, self.config.int('max_authorization_attempts'),
                                  self.config.int('authorization_delay'), Hooks(self.config.hooks))


class VerifyAction(Action):
    has_acme_client = False

    def run(self, context: CertificateContext):
        log.info("Verify certificates")

        verify_certificate_installation(context, self.config.int('max_ocsp_verify_attempts'), self.config.int('ocsp_verify_retry_delay'))
