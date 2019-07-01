import argparse
import contextlib
import fcntl
import logging
import os
import random
import sys
import time
from typing import List, Tuple

from acme import client

from . import AcmeError, VERSION, acme, actions
from .config import Configuration
from .context import CertificateContext
from .logging import PROGRESS, log
from .update import UpdateAction


class AcmeManager:

    def __init__(self, script_dir):
        self.script_dir = script_dir

        argparser = argparse.ArgumentParser(description='ACME Certificate Manager')

        argparser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)

        argparser.add_argument('-c', '--config',
                               dest='config_path', default='certmgr.json', metavar='CONFIG_PATH',
                               help='Specify file path for config')
        argparser.add_argument('-w', '--randomwait',
                               action='store_true', dest='random_wait', default=False,
                               help='Wait for a random time before executing')

        # Logging options
        argparser.add_argument('-q', '--quiet',  # error
                               action='store_true', dest='quiet', default=False,
                               help="Don't print status messages to stdout or warnings to stderr")
        argparser.add_argument('-v', '--verbose', '--info',
                               action='store_true', dest='verbose', default=False,
                               help='Print more detailed status messages to stdout')
        argparser.add_argument('-d', '--debug',
                               action='store_true', dest='debug', default=False,
                               help='Print detailed debugging information to stdout')

        argparser.add_argument('--color',
                               action='store_true', dest='color', default=True,
                               help='Colorize output')
        argparser.add_argument('--no-color',
                               action='store_true', dest='no_color', default=False,
                               help='Suppress colorized output')

        subparsers = argparser.add_subparsers(description='acmetool subcommand', dest='action')

        action = subparsers.add_parser('check', help='check installed files permissions and symlinks')
        actions.CheckAction.add_arguments(action)

        action = subparsers.add_parser('revoke', help='revoke certificates')
        actions.RevokeAction.add_arguments(action)

        action = subparsers.add_parser('auth', help='perform domain authentification')
        actions.AuthAction.add_arguments(action)

        action = subparsers.add_parser('update', help='update keys, certificates, oscp, sct and params')
        UpdateAction.add_arguments(action)

        action = subparsers.add_parser('verify', help='verify installed certificates')
        actions.VerifyAction.add_arguments(action)

        action = subparsers.add_parser('cleanup', help='remove old archives')
        actions.PruneAction.add_arguments(action)

        self.args = argparser.parse_args()
        if not getattr(self.args, 'cls', None):
            self.args = argparser.parse_args(sys.argv[1:] + ['update'])

        level = PROGRESS
        if self.args.quiet:
            level = logging.WARNING
        elif self.args.debug:
            level = logging.DEBUG
        elif self.args.verbose:
            level = logging.INFO

        # reset root logger
        log.reset(self.args.color and not self.args.no_color, level)

        self.config = Configuration.load(self.args.config_path, ('.', os.path.join('/etc', 'certmgr'), self.script_dir))
        # update color setting
        if not self.args.no_color:
            log.color = self.config.bool('color_output')

    def connect_client(self) -> client.ClientV2:
        account_dir = self.config.account_dir
        archive_dir = self.config.archive_dir('client')
        with log.prefix('[acme] '):
            return acme.connect_client(account_dir, self.config.account['email'], self.config.get('acme_directory_url'),
                                       self.config.account.get('passphrase'), archive_dir)

    def _run(self):
        certs = {}
        contexts = []
        for certificate_name in self.args.certificate_names or self.config.certificate_names():
            cert = self.config.certificate(certificate_name)
            if not cert:
                log.warning("requested certificate '%s' does not exists in config", certificate_name)
                continue
            if len(cert) > 1:
                log.warning("[%s] ambiguous certificate alias. Use the certificate name instead.", certificate_name)
                continue
            cert = cert[0]
            if cert.name in certs:
                log.info("requesting duplicated certificate (%s and %s)", certs[cert.name], certificate_name)
            else:
                contexts.append(CertificateContext(cert, self.config.data_dir, self.config.path))
                certs[cert.name] = certificate_name

        if not contexts:
            log.warning("nothing to process !")
            return (), ()

        ok = []
        errors = []
        acme_client = None
        cls = self.args.cls
        if cls.has_acme_client:
            acme_client = self.connect_client()
        action = cls(self.config, self.args, contexts, acme_client)
        for context in contexts:
            try:
                with log.prefix('[{}] '.format(context.name)):
                    action.run(context)
                ok.append(context.name)
            except AcmeError as e:
                log.error("[%s] processing failed. No files updated: %s", context.name, str(e), print_exc=True)
                errors.append(context.name)

        action.finalize()
        return ok, errors

    def run(self) -> Tuple[List, List]:
        lock_path = self.config.get('lock_file')
        if self.args.random_wait:
            delay_seconds = min(random.randrange(min(self.config.int('min_run_delay'), self.config.int('max_run_delay')),
                                                 max(self.config.int('min_run_delay'), self.config.int('max_run_delay'))), 86400)

            def _plural(duration, unit):
                if 0 < duration:
                    return '{duration} {unit}{plural} '.format(duration=duration, unit=unit, plural='' if (1 == duration) else 's')
                return ''

            log.debug('Waiting for %s%s%s',
                      _plural(int(delay_seconds / 3600), 'hour'), _plural(int((delay_seconds % 3600) / 60), 'minute'),
                      _plural((delay_seconds % 60), 'second'))
            time.sleep(delay_seconds)
        if lock_path:
            lock_file = open(lock_path, 'wb')

            if not try_lock(lock_file):
                if self.args.random_wait:
                    log.debug('Waiting for other running client instance')
                    while not try_lock(lock_file):
                        time.sleep(random.randrange(5, 30))
                else:
                    raise AcmeError('Client already running')

            with contextlib.closing(lock_file):
                return self._run()
        else:
            # not lock path specified.
            return self._run()


def try_lock(lock_file) -> bool:
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
