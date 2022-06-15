import abc
import argparse
import datetime
import os
import shutil
import stat
import sys
from abc import ABC
from argparse import Namespace
from os import read
from typing import Dict, List, Optional, Tuple

import OpenSSL
import josepy
from cryptography.x509 import load_pem_x509_csr

from . import AcmeError, acme
from .auth import authorize
from .config import CertificateDef, Configuration
from .context import CertificateContext, CertificateItem
from .crypto import PrivateKey
from .logging import log
from .utils import ArchiveOperation, FileOwner, Hooks, commit_file_transactions, dirmode
from .verify import verify_certificate_installation


class Action(ABC):
    def __init__(self, config: Configuration, args: Namespace):
        self.config = config
        self.args = args

        self.contexts: List[CertificateContext] = self.parse_arguments(config, args)

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser):
        parser.add_argument('certificate_names', nargs='*')
        parser.set_defaults(cls=cls)

    @classmethod
    def parse_arguments(cls, config: Configuration, args: Namespace) -> List[CertificateContext]:
        certs = {}
        contexts = []
        for certificate_name in args.certificate_names or config.certificate_names():
            certificates = config.certificate(certificate_name)
            if not certificates:
                log.warning("requested certificate '%s' does not exists in config", certificate_name)
                continue
            if len(certificates) > 1:
                log.warning("[%s] ambiguous certificate alias. Use the certificate name instead.", certificate_name)
                continue
            cert = certificates[0]
            if cert.name in certs:
                log.info("requesting duplicated certificate (%s and %s)", certs[cert.name], certificate_name)
            else:
                contexts.append(CertificateContext(cert, config.data_dir, config.path))
                certs[cert.name] = certificate_name

        return contexts

    def execute(self) -> Tuple[List, List]:
        if not self.contexts:
            log.warning("nothing to process !")
            return [], []

        ok = []
        errors = []
        for context in self.contexts:
            try:
                with log.prefix(f'[{context.name}] '):
                    self.run(context)
                ok.append(context.name)
            except AcmeError as e:
                log.error("[%s] processing failed. No files updated: %s", context.name, str(e), print_exc=True)
                errors.append(context.name)

        self.finalize()
        return ok, errors

    @abc.abstractmethod
    def run(self, context: CertificateContext):
        raise NotImplementedError()

    def finalize(self):
        pass


class AcmeActionMixin:

    def __init__(self, config: Configuration, args: Namespace):
        super().__init__(config, args)
        account_dir = config.account_dir
        archive_dir = config.archive_dir('client')
        with log.prefix('[acme] '):
            self.acme_client = acme.connect_client(account_dir, config.account['email'], config.get('acme_directory_url'),
                                                   config.account.get('passphrase'), archive_dir)


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


def update_links(root: str, context: CertificateContext):
    log.info('Update symlinks')

    with log.prefix('  - '):
        # process directories links (alt names -> common name)
        for name in context.alt_names:
            if name == context.common_name:
                continue
            link_path = os.path.join(root, name)
            if name in context.config.no_link:
                # FIXME: remove is not referenced by an other certificate
                log.debug("skipping '%s' link generation", name)
                continue

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

    def __init__(self, config: Configuration, args: Namespace):
        super().__init__(config, args)
        self._checked = dict()

    @staticmethod
    def _check(file: str, mode: int, owner: FileOwner):
        try:
            s = os.stat(file, follow_symlinks=False)
            log.debug('checking path %s', file)
            if stat.S_IMODE(s.st_mode) != mode:
                log.progress('file permission should be %s not %s', oct(mode), oct(stat.S_IMODE(s.st_mode)))
                os.chmod(file, mode)

            if s.st_uid != owner.uid or s.st_gid != owner.gid:
                log.progress('file "%s" owner/group should be %s/%s not %s/%s',
                             file, owner.uid, owner.gid, s.st_uid, s.st_gid)
                os.chown(file, owner.uid, owner.gid)
        except FileNotFoundError:
            log.debug('skipping non existing path %s', file)
            pass

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
            self._check_file(context.params_path, 0o640, owner)
        for item in context:
            with log.prefix(f"  - [{item.type.upper()}] "):
                # Private Keys
                self._check_file(item.key_path(), 0o640, owner)
                self._check_file(item.key_path(full=True), 0o640, owner)

                # Certificate
                self._check_file(item.certificate_path(), 0o644, owner)
                self._check_file(item.certificate_path(full=True), 0o644, owner)
                self._check_file(item.chain_path(), 0o644, owner)

                # OCSP
                self._check_file(item.ocsp_path(), 0o644, owner)

                for ct_log in context.config.ct_submit_logs:
                    self._check_file(item.sct_path(ct_log), 0o644, owner)

        # check symlinks
        update_links(self.config.data_dir, context)

    def finalize(self):
        owner = FileOwner(os.getuid(), os.getgid(), True)
        account_dir = self.config.account_dir
        # Check global file here
        with log.prefix("  - "):
            self._check_file(os.path.join(account_dir, 'client.key'), 0o600, owner)
            self._check_file(os.path.join(account_dir, 'registration.json'), 0o600, owner)


def prune_achives(archive_dir: Optional[str], days: int):
    if not archive_dir or days <= 0:
        return None

    try:
        filenames = os.listdir(archive_dir)
    except FileNotFoundError:
        return

    prune_date = datetime.datetime.now() - datetime.timedelta(days=days)
    prune_date = prune_date.replace(hour=0, minute=0, second=0, microsecond=0)
    log.debug("Pruning archives older than %s in '%s'", prune_date, archive_dir)

    for entry in filenames:
        try:
            date = datetime.datetime.strptime(entry, '%Y_%m_%d_%H%M%S')
        except ValueError:
            continue
        if date < prune_date:
            try:
                log.progress("removing archive %s", entry)
                shutil.rmtree(os.path.join(archive_dir, entry))
            except Exception as e:
                log.warning("error removing acrhive dir %s: %s", entry, str(e))


class PruneAction(Action):

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser):
        super().add_arguments(parser)
        parser.add_argument('--days', required=False,
                            type=int, dest='days', default=-1,
                            help='use to override archive_days config')

    def __init__(self, config: Configuration, args: Namespace):
        super().__init__(config, args)
        self.days = self.args.days
        if self.days < 0:
            self.days = self.config.int('archive_days')

    def run(self, context: CertificateContext):
        prune_achives(os.path.join(self.config.data_dir, 'archives', context.name), self.days)

    def finalize(self):
        prune_achives(os.path.join(self.config.data_dir, 'archives', 'account'), self.days)


class RevokeAction(AcmeActionMixin, Action):

    def run(self, context: CertificateContext):
        log.info("Revoking Certificates")

        certificate_count = 0
        revoked_certificates = []
        for item in context:
            with log.prefix(f"  - [{item.type.upper()}] "):
                cert = item.certificate
                if cert:
                    certificate_count += 1
                    try:
                        log.debug('revoking certificate')
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.encode())
                        self.acme_client.revoke(josepy.ComparableX509(x509), 0)
                        revoked_certificates.append(item)
                        log.progress('certificate revoked')
                    except Exception as error:
                        log.warning('Failed to revoke certificate: %s', str(error))
                else:
                    log.warning('certificate not found')

        with log.prefix("  - "):
            ops = [ArchiveOperation('certificates', context.params_path)]
            for item in revoked_certificates:  # type: CertificateItem
                ops.append(ArchiveOperation('certificates', item.certificate_path()))
                ops.append(ArchiveOperation('certificates', item.certificate_path(full=True)))
                ops.append(ArchiveOperation('certificates', item.chain_path()))

                ops.append(ArchiveOperation('keys', item.key_path()))
                ops.append(ArchiveOperation('keys', item.key_path(full=True)))

                ops.append(ArchiveOperation('meta', item.ocsp_path()))
                for ct_log in context.config.ct_submit_logs:
                    ops.append(ArchiveOperation('meta', item.sct_path(ct_log)))
            commit_file_transactions(ops, self.config.archive_dir(context.name))


class AuthAction(AcmeActionMixin, Action):

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser):
        super().add_arguments(parser)
        parser.add_argument('--csr',
                            action='store_true', default=False,
                            help='interpret positional arguments as CSR instead of certificate names')

    @classmethod
    def parse_arguments(cls, config: Configuration, args: Namespace) -> List[CertificateContext]:
        if not args.csr:
            return super().parse_arguments(config, args)

        # This is CSR -> parse them
        return []

    def execute(self) -> Tuple[List, List]:
        if not self.args.csr:
            return super().execute()

        ok = []
        errors = []
        # process raw input
        try:
            raw = sys.stdin.buffer.read()
            csr = load_pem_x509_csr(raw)
            with log.prefix('[CSR] '):
                order = authorize(csr, self.config.auth, self.acme_client, Hooks(self.config.hooks))
                order.update(csr_pem=None)
            ok.append("CSR")
        except AcmeError as e:
            log.error("[CSR] processing failed. No files updated: %s", str(e), print_exc=True)
            errors.append("CSR")
        return ok, errors

    def run(self, context: CertificateContext):
        log.info("Process Authorization")

        cert = context.config
        with log.prefix("  - "):
            # until acme provide a clean way to create an order without using a CSR, we just create a dummy CSR …
            key = PrivateKey.create("ecdsa", "secp256r1")
            csr = key.create_csr(cert.common_name, cert.alt_names)
            # … and remove it from the order afterward
            order = authorize(csr, cert.auth, self.acme_client, Hooks(self.config.hooks))
            order.update(csr_pem=None)


class VerifyAction(Action):

    def run(self, context: CertificateContext):
        log.info("Verify certificates")

        verify_certificate_installation(context)
