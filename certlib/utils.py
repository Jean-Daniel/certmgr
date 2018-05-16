import base64
import datetime
import logging
import os
import shlex
import subprocess
import tempfile
from collections import OrderedDict
from typing import Optional, Tuple, Iterable, List

import collections
import requests

from .crypto import Certificate
from .logging import log


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
FileOwner = collections.namedtuple('FileOwner', ('uid', 'gid', 'is_self'))


def dirmode(mode: int) -> int:
    if mode & 0o700:
        mode |= 0o100
    if mode & 0o070:
        mode |= 0o010
    if mode & 0o007:
        mode |= 0o001
    return mode


def makedir(dir_path: str, chmod: int = None, owner: FileOwner = None):
    try:
        os.makedirs(dir_path, dirmode(chmod))
    except FileExistsError:
        # try to guess dir mode for a file mode
        if chmod:
            try:
                os.chmod(dir_path, dirmode(chmod))
            except PermissionError as e:
                logging.warning('Unable to set directory mode for %s: %s', dir_path, str(e))

    if owner and not owner.is_self:
        try:
            os.chown(dir_path, owner.uid, owner.gid)
        except PermissionError as e:
            logging.warning('Unable to set directory mode for %s: %s', dir_path, str(e))


def open_file(file_path, mode='r', chmod=0o640):
    def opener(path, flags):
        return os.open(path, flags, mode=chmod)

    if (('w' in mode) or ('a' in mode)) and isinstance(file_path, str):
        makedir(os.path.dirname(file_path), chmod=chmod)
    return open(file_path, mode, opener=opener)


def rename_file(old_file_path: str, new_file_path: str, chmod: int = None, owner: FileOwner = None, timestamp=None) -> str:
    makedir(os.path.dirname(new_file_path), chmod, owner)
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
    if owner and not owner.is_self:
        try:
            os.chown(new_file_path, owner.uid, owner.gid)
        except PermissionError as error:
            logging.warning('Unable to set file ownership for "%s" to %s:%s: %s', new_file_path, owner.uid, owner.gid, str(error))
    return new_file_path


def archive_file(file_type, file_path: str, archive_dir: str, archive_date: datetime.datetime) -> Optional[Tuple[str, str]]:
    if archive_dir and os.path.isfile(file_path) and (not os.path.islink(file_path)):
        archive_file_path = os.path.join(archive_dir, archive_date.strftime('%Y_%m_%d_%H%M%S') if archive_date else '',
                                         file_type + '-' + os.path.basename(file_path))
        makedir(os.path.dirname(archive_file_path), 0o640)
        os.rename(file_path, archive_file_path)
        log.debug('Archived "%s" as "%s"', file_path, archive_file_path)
        return file_path, archive_file_path
    return None


class FileTransaction(object):
    __slots__ = ['file', 'temp_file_path', 'file_type', 'file_path', 'chmod', 'owner', 'timestamp', 'message']
    tempdir = None

    def __init__(self, file_type, file_path, chmod: int = None, owner: FileOwner = None, timestamp: datetime.datetime = None, mode='wb'):
        self.file_type = file_type
        self.file_path = file_path
        self.timestamp = timestamp
        self.chmod = chmod
        self.owner = owner
        self.message = ''

        temp_fd, self.temp_file_path = tempfile.mkstemp(dir=FileTransaction.tempdir, text='b' not in mode)
        self.file = open(temp_fd, mode)

    def __del__(self):
        if self.file:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(self, ty, value, traceback):
        if self.file:
            self.file.close()

    def write(self, data):
        self.file.write(data)

    def apply(self, archive_dir: str, archive_date: datetime.datetime):
        pass

    def revert(self):
        pass

    def cleanup(self):
        pass


def commit_file_transactions(file_transactions: Iterable[FileTransaction], archive_dir: Optional[str] = None):
    if not file_transactions:
        return

    log.debug('Committing file transaction')
    archived_files = []
    committed_files = []
    # archive dir is required to commit a transaction safely
    if archive_dir is None:
        archive_dir = FileTransaction.tempdir
    try:
        with log.prefix(" - "):
            archive_date = datetime.datetime.now()
            for file_transaction in file_transactions:
                archived_file = archive_file(file_transaction.file_type, file_transaction.file_path, archive_dir, archive_date)
                if archived_file:
                    archived_files.append(archived_file)

                file = rename_file(file_transaction.temp_file_path, file_transaction.file_path,
                                   chmod=file_transaction.chmod, owner=file_transaction.owner, timestamp=file_transaction.timestamp)
                committed_files.append(file)
                log.debug("%s: %s", file_transaction.message or 'file saved', file_transaction.file_path)
    except Exception as e:  # restore any archived files
        log.error('File transaction error. Rolling back changes')
        with log.prefix(" - "):
            for committed_file_path in committed_files:
                try:
                    os.remove(committed_file_path)
                    log.debug('%s removed', committed_file_path)
                except FileNotFoundError:
                    pass
            for original_file_path, archived_file_path in archived_files:
                try:
                    os.rename(archived_file_path, original_file_path)
                    log.debug('%s restored', original_file_path)
                except FileNotFoundError:
                    log.warning("%s restoration failed", original_file_path)
        raise e


class Hooks(object):

    def __init__(self, commands: dict):
        self._hooks = OrderedDict()
        self._commands = commands

    # Hook Management
    def add(self, hook_name: str, **kwargs):
        hooks = self._commands[hook_name]
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
        except KeyError as e:
            log.warning('Invalid hook specification for %s, unknown key %s', hook_name, e)

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


# SCT Support
SCTLog = collections.namedtuple('SCTLog', ('name', 'id', 'url'))
SCTData = collections.namedtuple('SCTData', ['version', 'id', 'timestamp', 'extensions', 'signature'])


def fetch_sct(ct_log: SCTLog, certificate: Certificate, chain: List[Certificate]) -> SCTData:
    certificates = ([base64.b64encode(certificate.encode(pem=False)).decode('ascii')]
                    + [base64.b64encode(chain_certificate.encode(pem=False)).decode('ascii') for chain_certificate in chain])

    req = requests.post(ct_log.url + '/ct/v1/add-chain', json={'chain': certificates})
    try:
        if req.status_code == 200:
            sct = req.json()
            sid = sct.get('id')
            ext = sct.get('extensions')
            sign = sct.get('signature')
            return SCTData(sct.get('sct_version'), base64.b64decode(sid) if sid else b'', sct.get('timestamp'),
                           base64.b64decode(ext) if ext else b'', base64.b64decode(sign) if sign else None)
        if 400 <= req.status_code < 500:
            log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)\n%s', ct_log.name, req.status_code, req.reason, req.content())
        else:
            log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)', ct_log.name, req.status_code, req.reason)
    except Exception as e:
        log.warning('Unable to retrieve SCT from log %s: %s', ct_log.name, str(e))


def process_running(pid_file_path):
    try:
        with open(pid_file_path) as pid_file:
            return -1 < os.getsid(int(pid_file.read()))
    except Exception:
        pass
    return False
