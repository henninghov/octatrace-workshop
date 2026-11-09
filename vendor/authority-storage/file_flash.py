"""Host file-backed flash semantics. Never use this adapter for device flashing.

fsync/close/reopen evidence is not electrical durability, wear or target SDK proof.
The caller owns an exclusive single writer. Hooks model interruption/fault injection.
"""
import os
from pathlib import Path
SIZE = 24576
PAGE = 4096
ERROR = 'Invalid reference flash operation'


def fail():
    raise ValueError(ERROR)


class FileFlash:
    def __init__(self, path, hook=None):
        self.path = Path(path)
        if self.path.stat().st_size != SIZE:
            fail()
        self.hook = hook or (lambda *args:None)

    @classmethod
    def create(cls, path):
        with Path(path).open('xb') as stream:
            stream.write(b'\xff'*SIZE)
            stream.flush()
            os.fsync(stream.fileno())
        return cls(path)

    def bounds(self, offset, size):
        if type(offset) is not int or type(size) is not int or offset < 0 or size <= 0 or offset+size > SIZE:
            fail()

    def read(self, offset, size):
        self.bounds(offset, size)
        self.hook('before_read', offset, size)
        with self.path.open('rb') as stream:
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            fail()
        self.hook('after_read', offset, size)
        return data

    def change(self, offset, data, stage):
        self.hook('before_'+stage, offset, len(data))
        with self.path.open('r+b') as stream:
            stream.seek(offset)
            if stream.write(data) != len(data):
                fail()
            stream.flush()
            os.fsync(stream.fileno())
        self.hook('after_'+stage, offset, len(data))
        return True

    def program(self, offset, data):
        if type(data) is not bytes or not data or len(data)>128 or type(offset) is not int or offset%4 or len(data)%4:
            fail()
        self.bounds(offset, len(data))
        old = self.read(offset, len(data))
        if any((a & b) != b for a,b in zip(old, data)):
            fail()
        return self.change(offset, data, 'program')

    def erase_page(self, page):
        if type(page) is not int or not 0 <= page < SIZE//PAGE:
            fail()
        return self.change(page*PAGE, b'\xff'*PAGE, 'erase')
