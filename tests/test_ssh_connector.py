"""
Tests for ssh_connector.py.

paramiko is mocked at the sys.modules level before the module is imported
so no real SSH dependency is required to run the suite.
"""
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest

# ------------------------------------------------------------------
# Pre-mock paramiko before importing ssh_connector
# ------------------------------------------------------------------
sys.modules.setdefault("paramiko", MagicMock())

from ssh_connector import SSHOverWebSocket  # noqa: E402
from conftest import FakeSocket  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_connector() -> SSHOverWebSocket:
    """Return an SSHOverWebSocket with a mocked transport, no real socket."""
    conn = SSHOverWebSocket.__new__(SSHOverWebSocket)
    conn.transport = MagicMock()
    conn.transport.open_channel.return_value = MagicMock()
    conn._open_ssh_channel = MagicMock()  # prevent real thread spawning
    return conn


def make_socks4_request(
    cmd: int = 1,
    port: int = 80,
    ip: bytes = b"\xc0\xa8\x00\x01",
    user_id: bytes = b"",
    domain: bytes | None = None,
) -> bytes:
    buf = b"\x04" + bytes([cmd]) + struct.pack(">H", port) + ip
    buf += user_id + b"\x00"
    if domain is not None:
        buf += domain + b"\x00"
    return buf


def make_socks5_request(
    methods: bytes = b"\x00",
    cmd: int = 0x01,
    atyp: int = 0x01,
    addr: bytes = b"\x01\x02\x03\x04",
    port: int = 80,
) -> bytes:
    buf = b"\x05" + bytes([len(methods)]) + methods
    buf += b"\x05" + bytes([cmd]) + b"\x00" + bytes([atyp])
    if atyp == 0x03:
        buf += bytes([len(addr)]) + addr
    else:
        buf += addr
    buf += struct.pack(">H", port)
    return buf


# ---------------------------------------------------------------------------
# TestHandleSocks4
# ---------------------------------------------------------------------------

class TestHandleSocks4:
    def test_connect_ipv4_sends_granted_and_opens_channel(self):
        data = make_socks4_request(cmd=1, port=8080, ip=b"\x01\x02\x03\x04")
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks4(sock)

        # First 2 bytes of response: granted
        assert bytes(sock.sent[:2]) == b"\x00\x5A"
        # Channel opened with correct host and port
        conn._open_ssh_channel.assert_called_once_with(sock, "1.2.3.4", 8080)

    def test_connect_socks4a_domain(self):
        data = make_socks4_request(
            cmd=1, port=443, ip=b"\x00\x00\x00\x01", domain=b"example.com"
        )
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks4(sock)

        assert bytes(sock.sent[:2]) == b"\x00\x5A"
        conn._open_ssh_channel.assert_called_once_with(sock, "example.com", 443)

    def test_bad_command_sends_rejected_and_closes(self):
        data = make_socks4_request(cmd=2, port=80, ip=b"\x01\x02\x03\x04")
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks4(sock)

        assert bytes(sock.sent[:2]) == b"\x00\x5B"
        assert sock.closed is True
        conn._open_ssh_channel.assert_not_called()

    def test_too_short_data_closes_without_channel(self):
        sock = FakeSocket(b"\x04\x01\x00")  # only 3 bytes, need ≥ 9
        conn = make_connector()

        conn._handle_socks4(sock)

        assert sock.closed is True
        conn._open_ssh_channel.assert_not_called()

    def test_ip_all_zeros_not_treated_as_socks4a(self):
        # ip_part[3] == 0 → condition fails → stays as plain IP
        data = make_socks4_request(cmd=1, port=80, ip=b"\x00\x00\x00\x00")
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks4(sock)

        conn._open_ssh_channel.assert_called_once_with(sock, "0.0.0.0", 80)


# ---------------------------------------------------------------------------
# TestHandleSocks5
# ---------------------------------------------------------------------------

class TestHandleSocks5:
    def test_ipv4_connect_success(self):
        data = make_socks5_request(atyp=0x01, addr=b"\x7f\x00\x00\x01", port=22)
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks5(sock)

        sent = bytes(sock.sent)
        assert sent[:2] == b"\x05\x00"  # method negotiation: no-auth chosen
        assert b"\x05\x00\x00\x01" in sent  # success reply prefix
        conn._open_ssh_channel.assert_called_once_with(sock, "127.0.0.1", 22)

    def test_domain_connect_success(self):
        domain = b"example.com"
        data = make_socks5_request(atyp=0x03, addr=domain, port=443)
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks5(sock)

        conn._open_ssh_channel.assert_called_once_with(sock, "example.com", 443)

    def test_ipv6_connect_success(self):
        import socket as _socket
        ipv6_bytes = b"\x00" * 15 + b"\x01"  # ::1
        data = make_socks5_request(atyp=0x04, addr=ipv6_bytes, port=80)
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks5(sock)

        expected_host = _socket.inet_ntop(_socket.AF_INET6, ipv6_bytes)
        conn._open_ssh_channel.assert_called_once_with(sock, expected_host, 80)

    def test_bad_cmd_sends_error_7_and_closes(self):
        data = make_socks5_request(cmd=0x02)  # BIND, not CONNECT
        sock = FakeSocket(data)
        conn = make_connector()

        conn._handle_socks5(sock)

        sent = bytes(sock.sent)
        assert b"\x05\x07" in sent  # command not supported
        assert sock.closed is True
        conn._open_ssh_channel.assert_not_called()

    def test_bad_atyp_sends_error_8_and_closes(self):
        # Build the request manually with an unsupported ATYP
        methods = b"\x00"
        buf = b"\x05" + bytes([len(methods)]) + methods
        buf += b"\x05\x01\x00\xff"  # ATYP = 0xFF
        buf += b"\x00\x50"           # dummy port bytes
        sock = FakeSocket(buf)
        conn = make_connector()

        conn._handle_socks5(sock)

        sent = bytes(sock.sent)
        assert b"\x05\x08" in sent  # address type not supported
        assert sock.closed is True

    def test_wrong_socks_version_closes_socket(self):
        # First 2 bytes: version=4 (SOCKS4, not 5)
        sock = FakeSocket(b"\x04\x01")
        conn = make_connector()

        conn._handle_socks5(sock)

        assert sock.closed is True
        conn._open_ssh_channel.assert_not_called()

    def test_too_short_initial_packet_closes(self):
        sock = FakeSocket(b"\x05")  # only 1 byte instead of 2
        conn = make_connector()

        conn._handle_socks5(sock)

        assert sock.closed is True


# ---------------------------------------------------------------------------
# TestSendSocks5Helpers
# ---------------------------------------------------------------------------

class TestSendSocks5Helpers:
    @pytest.mark.parametrize("err_code", [0x01, 0x05, 0x07, 0x08])
    def test_send_socks5_error_correct_bytes_and_closes(self, err_code):
        sock = FakeSocket()
        conn = make_connector()

        conn._send_socks5_error(sock, err_code)

        expected = b"\x05" + bytes([err_code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        assert bytes(sock.sent) == expected
        assert sock.closed is True

    def test_send_socks5_success_correct_bytes_does_not_close(self):
        sock = FakeSocket()
        conn = make_connector()

        conn._send_socks5_success(sock)

        assert bytes(sock.sent) == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        assert sock.closed is False


# ---------------------------------------------------------------------------
# TestForwardData
# ---------------------------------------------------------------------------

class TestForwardData:
    def test_forwards_data_and_closes_only_src(self):
        src = FakeSocket(b"hello world")
        dst = FakeSocket()
        conn = make_connector()

        conn._forward_data(src, dst)

        assert b"hello world" in bytes(dst.sent)
        assert src.closed is True
        assert dst.closed is False

    def test_exception_in_sendall_closes_src_not_raise(self):
        src = FakeSocket(b"data")
        dst = MagicMock()
        dst.sendall.side_effect = OSError("broken pipe")
        conn = make_connector()

        # Must not raise
        conn._forward_data(src, dst)

        assert src.closed is True
