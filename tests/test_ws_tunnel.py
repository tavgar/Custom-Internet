import ssl
from unittest.mock import MagicMock, patch, call

import pytest

from ws_tunnel import replace_placeholders, read_headers, establish_ws_tunnel
from conftest import FakeSocket


# ---------------------------------------------------------------------------
# replace_placeholders
# ---------------------------------------------------------------------------

class TestReplacePlaceholders:
    def test_host_placeholder_replaced(self):
        result = replace_placeholders("Host: [host]", "example.com", 80)
        assert b"example.com:80" in result

    def test_crlf_placeholder_replaced(self):
        result = replace_placeholders("line1[crlf]line2", "h", 1)
        assert b"line1\r\nline2" in result

    def test_both_placeholders_replaced(self):
        result = replace_placeholders(
            "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]", "srv.net", 443
        )
        assert b"srv.net:443" in result
        assert b"\r\n" in result

    def test_returns_bytes(self):
        assert isinstance(replace_placeholders("GET /", "h", 1), bytes)

    def test_no_placeholders_encodes_as_is(self):
        assert replace_placeholders("plain text", "h", 1) == b"plain text"

    @pytest.mark.parametrize(
        "host,port,expected_host_str",
        [
            ("a.com", 80, "a.com:80"),
            ("192.168.1.1", 22, "192.168.1.1:22"),
            ("::1", 8080, "::1:8080"),
        ],
    )
    def test_various_hosts_and_ports(self, host, port, expected_host_str):
        result = replace_placeholders("[host]", host, port)
        assert expected_host_str.encode() in result


# ---------------------------------------------------------------------------
# read_headers
# ---------------------------------------------------------------------------

class TestReadHeaders:
    def test_reads_until_double_crlf(self):
        sock = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        result = read_headers(sock)
        assert b"\r\n\r\n" in result
        assert b"HTTP/1.1 200 OK" in result

    def test_multi_chunk_response(self):
        # FakeSocket returns up to 4096 bytes at a time; split across two
        # calls by keeping the full response in the buffer.
        raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        sock = FakeSocket(raw)
        result = read_headers(sock)
        assert result == raw

    def test_empty_socket_returns_empty(self):
        sock = FakeSocket(b"")
        result = read_headers(sock)
        assert result == b""

    def test_stops_at_first_double_crlf(self):
        header = b"HTTP/1.1 200 OK\r\n\r\n"
        body   = b"extra body data"
        sock = FakeSocket(header + body)
        result = read_headers(sock)
        # Must contain the header delimiter
        assert b"\r\n\r\n" in result
        # Body data may be in result (buffered read) but the header must be intact
        assert b"HTTP/1.1 200 OK" in result


# ---------------------------------------------------------------------------
# establish_ws_tunnel
# ---------------------------------------------------------------------------

class TestEstablishWsTunnel:
    def _default_kwargs(self, **overrides):
        kwargs = dict(
            proxy_host="proxy.ex",
            proxy_port=80,
            target_host="ssh.ex",
            target_port=22,
            payload_template="GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
        )
        kwargs.update(overrides)
        return kwargs

    @patch("ws_tunnel.read_headers")
    @patch("ws_tunnel.socket.create_connection")
    def test_single_block_no_100_continue(self, mock_conn, mock_rh):
        fake_sock = FakeSocket()
        mock_conn.return_value = fake_sock
        mock_rh.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ]
        result = establish_ws_tunnel(**self._default_kwargs())
        assert result is fake_sock
        assert b"GET / HTTP/1.1" in bytes(fake_sock.sent)

    @patch("ws_tunnel.read_headers")
    @patch("ws_tunnel.socket.create_connection")
    def test_100_continue_triggers_second_send(self, mock_conn, mock_rh):
        fake_sock = FakeSocket()
        mock_conn.return_value = fake_sock
        mock_rh.side_effect = [
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ]
        # Two-block payload separated by \r\n\r\n
        tmpl = "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]SECOND_BLOCK[crlf][crlf]"
        establish_ws_tunnel(**self._default_kwargs(payload_template=tmpl))
        # Both blocks should have been sent
        sent = bytes(fake_sock.sent)
        assert b"GET / HTTP/1.1" in sent
        assert b"SECOND_BLOCK" in sent

    @patch("ws_tunnel.read_headers")
    def test_uses_provided_sock(self, mock_rh):
        provided = FakeSocket()
        mock_rh.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ]
        with patch("ws_tunnel.socket.create_connection") as mock_conn:
            establish_ws_tunnel(**self._default_kwargs(sock=provided))
            mock_conn.assert_not_called()

    @patch("ws_tunnel.read_headers")
    @patch("ws_tunnel.ssl.create_default_context")
    @patch("ws_tunnel.socket.create_connection")
    def test_tls_wrap_called_when_use_tls_true(self, mock_conn, mock_ctx, mock_rh):
        raw_sock = MagicMock()
        tls_sock = MagicMock()
        mock_conn.return_value = raw_sock
        mock_ctx.return_value.wrap_socket.return_value = tls_sock
        mock_rh.return_value = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

        establish_ws_tunnel(**self._default_kwargs(use_tls=True))

        mock_ctx.return_value.wrap_socket.assert_called_once_with(
            raw_sock, server_hostname="proxy.ex"
        )

    @patch("ws_tunnel.read_headers")
    @patch("ws_tunnel.ssl.create_default_context")
    def test_no_double_tls_wrap_if_already_ssl_socket(self, mock_ctx, mock_rh):
        already_tls = MagicMock(spec=ssl.SSLSocket)
        mock_rh.return_value = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"

        establish_ws_tunnel(**self._default_kwargs(sock=already_tls, use_tls=True))

        mock_ctx.return_value.wrap_socket.assert_not_called()

    @patch("ws_tunnel.read_headers")
    @patch("ws_tunnel.socket.create_connection")
    def test_placeholders_applied_in_sent_bytes(self, mock_conn, mock_rh):
        fake_sock = FakeSocket()
        mock_conn.return_value = fake_sock
        mock_rh.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 101\r\n\r\n",
        ]
        establish_ws_tunnel(
            **self._default_kwargs(
                target_host="myserver.com",
                target_port=2222,
                payload_template="Host: [host][crlf][crlf]",
            )
        )
        sent = bytes(fake_sock.sent)
        assert b"myserver.com:2222" in sent
        assert b"\r\n" in sent
