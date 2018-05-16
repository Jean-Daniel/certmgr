import contextlib
import logging
import sys
from typing import Optional


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


@contextlib.contextmanager
def swap(values: dict, key: str, value: str):
    orig = values[key]
    values[key] = value
    yield
    values[key] = orig


class _Logger(logging.LoggerAdapter):

    def __init__(self, logger):
        super().__init__(logger, {'prefix': ''})
        self._stream = None  # type: logging.StreamHandler
        self._file = None

    def prefix(self, prefix: str):
        return swap(self.extra, 'prefix', self.extra['prefix'] + prefix)

    @property
    def color(self) -> bool:
        return self._stream and isinstance(self._stream.formatter, ColorFormatter)

    @color.setter
    def color(self, value: bool):
        if value:
            if not self._stream:
                self.reset(True)
            else:
                self._stream.setFormatter(ColorFormatter())
        elif self.color:
            self._stream.setFormatter(_Formatter())

    @property
    def file(self) -> Optional[str]:
        return self._file.baseFilename if self._file else None

    @file.setter
    def file(self, path: Optional[str]):
        if self._file:
            self.logger.removeHandler(self._file)
            self._file = None
        if path:
            self._file = logging.FileHandler(path, encoding='UTF-8')
            self.logger.addHandler(self._file)

    def reset(self, color: bool):
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
        # create console handler
        self._stream = logging.StreamHandler(sys.stderr)
        # enable color output
        if sys.stderr.isatty() and color:
            self._stream.setFormatter(ColorFormatter())
        else:
            self._stream.setFormatter(_Formatter())
        self.logger.addHandler(self._stream)


log = _Logger(logging.getLogger("certmgr"))
