import contextlib
import logging
import sys
import traceback
from typing import Optional

PROGRESS = 25
logging.addLevelName(PROGRESS, "PROGRESS")


class _Formatter(logging.Formatter):
    def __init__(self):
        super().__init__(fmt='{prefix}{message}', style='{')


class ColorFormatter(_Formatter):
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


class _Logger(logging.LoggerAdapter):

    def __init__(self, logger):
        super().__init__(logger, {'prefix': ''})
        self._stream = None  # type: logging.StreamHandler
        self._file = None
        self.setLevel(logging.DEBUG)

    def process(self, msg, kwargs):
        extra = kwargs.get('extra')
        if extra:
            kwargs["extra"] = dict(self.extra)
            kwargs["extra"].update(extra)
        else:
            kwargs["extra"] = self.extra
        return msg, kwargs

    @contextlib.contextmanager
    def prefix(self, prefix: str):
        orig = self.extra['prefix']
        self.extra['prefix'] += prefix
        yield
        self.extra['prefix'] = orig

    @property
    def color(self) -> bool:
        return self._stream and isinstance(self._stream.formatter, ColorFormatter)

    @color.setter
    def color(self, value: bool):
        if value:
            if not self._stream:
                self.reset(True, logging.NOTSET)
            else:
                self._stream.setFormatter(ColorFormatter())
        elif self.color:
            self._stream.setFormatter(_Formatter())

    @property
    def file(self) -> Optional[str]:
        return self._file.baseFilename if self._file else None

    def set_file(self, path: Optional[str], level: int):
        if self._file:
            self.logger.removeHandler(self._file)
            self._file = None
        if path:
            self._file = logging.FileHandler(path, encoding='UTF-8')
            self._file.setFormatter(_Formatter())
            self._file.level = level
            self.logger.addHandler(self._file)

    def reset(self, color: bool, level: int):
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
        # create console handler
        self._stream = logging.StreamHandler(sys.stderr)
        self._stream.level = level
        # enable color output
        if sys.stderr.isatty() and color:
            self._stream.setFormatter(ColorFormatter())
        else:
            self._stream.setFormatter(_Formatter())
        self.logger.addHandler(self._stream)

    def debug(self, msg, *args, print_exc: bool = False, **kwargs):
        """
        Delegate a debug call to the underlying logger.
        """
        super().debug(msg, *args, **kwargs)
        if print_exc:
            traceback.print_exc()

    def info(self, msg, *args, print_exc: bool = False, **kwargs):
        """
        Delegate an info call to the underlying logger.
        """
        super().info(msg, *args, **kwargs)
        if print_exc and self.isEnabledFor(logging.DEBUG):
            traceback.print_exc()

    def progress(self, msg, *args, **kwargs):
        self.log(25, msg, *args, **kwargs)

    def warning(self, msg, *args, print_exc: bool = False, **kwargs):
        """
        Delegate a warning call to the underlying logger.
        """
        super().warning(msg, *args, **kwargs)
        if print_exc and self.isEnabledFor(logging.DEBUG):
            traceback.print_exc()

    def error(self, msg, *args, print_exc: bool = False, **kwargs):
        """
        Delegate an error call to the underlying logger.
        """
        super().error(msg, *args, **kwargs)
        if print_exc and self.isEnabledFor(logging.DEBUG):
            traceback.print_exc()

    def critical(self, msg, *args, print_exc: bool = False, **kwargs):
        """
        Delegate a critical call to the underlying logger.
        """
        super().critical(msg, *args, **kwargs)
        if print_exc and self.isEnabledFor(logging.DEBUG):
            traceback.print_exc()


log = _Logger(logging.getLogger("certmgr"))
