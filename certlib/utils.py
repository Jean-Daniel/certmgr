import abc
import base64
import contextlib
import datetime
import io
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


class Operation(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def apply(self, archive_dir: Optional[str]):
        pass

    @abc.abstractmethod
    def revert(self):
        pass

    def cleanup(self):
        pass


class WriteOperation(Operation):
    __slots__ = ['file_path', 'mode', 'owner', '_buffer', '_tmp_path', '_rmdir']

    def __init__(self, file_path: str, mode: int, owner: Optional[FileOwner] = None):
        self.file_path = file_path
        self.mode = mode
        self.owner = owner if owner and not owner.is_self else None

        self._tmp_path = None
        self._buffer = None  # type: io.BytesIO
        self._rmdir = False

    @contextlib.contextmanager
    def file(self, binary=True):
        assert not self._buffer
        self._buffer = io.BytesIO() if binary else io.StringIO()
        # noinspection PyBroadException
        try:
            yield self._buffer
        except Exception:
            self._buffer = None
            raise
        else:
            self._buffer.close()

    def tmp_path(self, archive_dir: Optional[str]):
        return tempfile.mktemp(prefix='.old-', dir=os.path.dirname(self.file_path))

    def apply(self, archive_dir: Optional[str]):
        tmp_path = self.tmp_path(archive_dir)
        try:
            os.makedirs(os.path.dirname(tmp_path), dirmode(self.mode or 0o700))
            self._rmdir = True
        except FileExistsError:
            pass

        # Move existing file out of the way
        try:
            os.rename(self.file_path, tmp_path)
            self._tmp_path = tmp_path
        except FileNotFoundError:
            pass

        if not self._buffer:
            return

        mode = 'wb' if isinstance(self._buffer, io.BytesIO) else 'w'
        with open(self.file_path, mode) as f:
            if self.mode:
                try:
                    os.fchmod(f.fileno(), self.mode)
                except PermissionError as error:
                    logging.warning('Unable to set file mode for "%s" to %s: %s', self.file_path, oct(self.mode), str(error))
            if self.owner:
                try:
                    os.fchown(f.fileno(), self.owner.uid, self.owner.gid)
                except PermissionError as error:
                    logging.warning('Unable to set file ownership for "%s" to %s:%s: %s', self.file_path, self.owner.uid, self.owner.gid, str(error))
            # noinspection PyTypeChecker
            f.write(self._buffer.getbuffer() if isinstance(self._buffer, io.BytesIO) else self._buffer.getvalue())
        self._buffer = None

    def revert(self):
        try:
            os.remove(self.file_path)
            log.debug('%s removed', self.file_path)
        except FileNotFoundError:
            pass

        if self._tmp_path:
            os.rename(self._tmp_path, self.file_path)
            log.debug('%s restored', self.file_path)
            self._tmp_path = None

    def cleanup(self):
        if self._tmp_path:
            try:
                os.remove(self._tmp_path)
            except FileNotFoundError:
                pass

            if self._rmdir:
                try:
                    os.removedirs(os.path.dirname(self._tmp_path))
                except (FileNotFoundError, OSError):
                    pass

            self._tmp_path = None


class ArchiveAndWriteOperation(WriteOperation):
    __slots__ = ['file_type', '_archived']

    def __init__(self, file_type: str, file_path: str, mode: int, owner: Optional[FileOwner] = None):
        super().__init__(file_path, mode, owner)
        self.file_type = file_type
        self._archived = False

    def tmp_path(self, archive_dir: Optional[str]):
        if archive_dir:
            self._archived = True
            return os.path.join(archive_dir, self.file_type + '-' + os.path.basename(self.file_path))
        # return a temporary path used to be able to revert in case of error
        return super().tmp_path(archive_dir)

    def cleanup(self):
        # skip cleanup step if file archived (should not be removed)
        if self._archived:
            return
        return super().cleanup()


class ArchiveOperation(ArchiveAndWriteOperation):

    def __init__(self, file_type: str, file_path: str):
        super().__init__(file_type, file_path, 0, None)

    def file(self):
        raise NotImplementedError("archive operation does not support writing. Use ArchiveAndWriteOperation instead.")


def commit_file_transactions(operations: Iterable[Operation], archive_dir: Optional[str] = None):
    if not operations:
        return

    log.debug('Committing file transaction')
    applied = []
    try:
        with log.prefix(" - "):
            for op in operations:
                op.apply(archive_dir)
                applied.append(op)
            # log.debug("%s: %s", file_transaction.message or 'file saved', file_transaction.file_path)
    except Exception as e:  # restore any archived files
        log.error('File transaction error. Rolling back changes')
        with log.prefix(" - "):
            for op in applied:
                try:
                    op.revert()
                except Exception as err:
                    log.error("reverting operation '%s' failed: %s", str(op), str(err))
        raise e
    else:
        for op in applied:
            try:
                op.cleanup()
            except Exception as err:
                log.error("cleanup operation '%s' failed: %s", str(op), str(err))


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
