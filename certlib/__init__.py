# certlib module


class AcmeError(Exception):

    def __init__(self, fmt, *args, **kwargs):
        super().__init__(fmt.format(*args, **kwargs))
