# certlib module
import logging

log = logging.getLogger("certmgr")

SUPPORTED_KEY_TYPES = ('rsa', 'ecdsa')


class AcmeError(Exception):

    def __init__(self, fmt, *args, **kwargs):
        super().__init__(fmt.format(*args, **kwargs))