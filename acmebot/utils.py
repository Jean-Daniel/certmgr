import datetime
import grp
import logging
import os
import pwd
import shlex
import subprocess
import tempfile
from collections import OrderedDict
from typing import Optional, Tuple, Iterable

import collections

from . import log


class ColorFormatter(logging.Formatter):
    _color_codes = {
        'black': 30,
        'red': 31,
        'green': 32,
        'yellow': 33,
        'blue': 34,
        'magenta': 35,
        'cyan': 36,
        'light gray': 37,
        'dark gray': 90,
        'light red': 91,
        'light green': 92,
        'light yellow': 93,
        'light blue': 94,
        'light magenta': 95,
        'light cyan': 96,
        'white': 97
    }
    _style_codes = {
        'normal': 0,
        'bold': 1,
        'bright': 1,
        'dim': 2,
        'underline': 4,
        'underlined': 4,
        'blink': 5,
        'reverse': 7,
        'invert': 7,
        'hidden': 8
    }

    def format(self, record: logging.LogRecord):
        style = 'normal'
        if hasattr(record, 'color'):
            color = record.color
        elif record.levelno >= logging.ERROR:
            color = 'red'
            style = 'bold'
        elif record.levelno >= logging.WARNING:
            color = 'yellow'
        elif record.levelno >= logging.INFO:
            color = 'dark gray'
        else:
            color = 'light gray'

        msg = super().format(record)
        return '\033[{style};{color}m{message}\033[0m'.format(color=self._color_codes[color], style=self._style_codes[style], message=msg)


def get_user_id(user_name: str) -> int:
    return pwd.getpwnam(user_name).pw_uid


def get_group_id(group_name: str) -> int:
    return grp.getgrnam(group_name).gr_gid


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
def makedir(dir_path: str, chmod: int = None, warn: bool = True):
    if not os.path.isdir(dir_path):
        try:
            os.makedirs(dir_path)
            if chmod:
                if chmod & 0o700:
                    chmod |= 0o100
                if chmod & 0o070:
                    chmod |= 0o010
                if chmod & 0o007:
                    chmod |= 0o001
                try:
                    os.chmod(dir_path, chmod)
                except PermissionError as error:
                    if warn:
                        logging.warning('Unable to set directory mode for %s: %s', dir_path, str(error))
        except Exception as error:
            if warn:
                logging.warning('Unable to create directory %s: %s', dir_path, str(error))


def open_file(file_path, mode='r', chmod=0o640, warn=True):
    def opener(path, flags):
        return os.open(path, flags, mode=chmod)

    if (('w' in mode) or ('a' in mode)) and isinstance(file_path, str):
        makedir(os.path.dirname(file_path), chmod=chmod, warn=warn)
    return open(file_path, mode, opener=opener)


FileOwner = collections.namedtuple('FileOwner', ('uid', 'gid', 'is_self'))


def rename_file(old_file_path: str, new_file_path: str, chmod: int = None, owner: FileOwner = None, timestamp=None):
    if os.path.isfile(old_file_path):
        makedir(os.path.dirname(new_file_path), chmod)
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
    return None


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
        archive_date = datetime.datetime.now()
        for file_transaction in file_transactions:
            archived_file = archive_file(file_transaction.file_type, file_transaction.file_path, archive_dir, archive_date)
            if archived_file:
                archived_files.append(archived_file)

            file = rename_file(file_transaction.temp_file_path, file_transaction.file_path,
                               chmod=file_transaction.chmod, owner=file_transaction.owner, timestamp=file_transaction.timestamp)
            if file:
                committed_files.append(file)
            log.debug(" - %s: %s", file_transaction.message or 'file saved', file_transaction.file_path)
    except Exception as error:  # restore any archived files
        log.error('File transaction error. Rolling back changes')
        for committed_file_path in committed_files:
            if committed_file_path:
                os.remove(committed_file_path)
                log.debug(' - removing %s', committed_file_path)
        for original_file_path, archived_file_path in archived_files:
            if original_file_path:
                os.rename(archived_file_path, original_file_path)
                log.debug(' - restoring %s', original_file_path)
        raise error


class Hooks(object):

    def __init__(self):
        self._hooks = OrderedDict()

    # Hook Management
    def add(self, hook_name: str, hooks, **kwargs):
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
        except KeyError as error:
            log.warning('Invalid hook specification for %s, unknown key %s', hook_name, error)

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


def process_running(pid_file_path):
    try:
        with open(pid_file_path) as pid_file:
            return -1 < os.getsid(int(pid_file.read()))
    except Exception:
        pass
    return False
