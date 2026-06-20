import os
import sys

# Make the repo root importable from the tests/ directory
sys.path.insert(0, os.path.dirname(__file__))

import pytest


class FakeSocket:
    """In-memory socket substitute for unit tests."""

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.sent = bytearray()
        self.closed = False
        self._timeout = None

    def recv(self, n: int, flags: int = 0) -> bytes:
        chunk = bytes(self._buf[:n])
        self._buf = self._buf[n:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True

    def settimeout(self, t) -> None:
        self._timeout = t

    def getsockname(self):
        return ("127.0.0.1", 9999)


@pytest.fixture
def fake_socket_factory():
    def _make(data: bytes = b"") -> FakeSocket:
        return FakeSocket(data)
    return _make
