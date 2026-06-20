from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Optional

import paramiko

logger = logging.getLogger(__name__)

# SOCKS4 response codes
_SOCKS4_GRANTED  = b"\x00\x5A"
_SOCKS4_REJECTED = b"\x00\x5B"

# SOCKS5 wire constants
_SOCKS5_NO_AUTH  = b"\x05\x00"
_SOCKS5_SUCCESS  = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"


class SSHOverWebSocket:
    """
    Wraps a Paramiko Transport (SSH) that runs on top of a raw
    WebSocket-upgraded socket, plus a local SOCKS server.
    """

    def __init__(
        self,
        ws_socket: socket.socket,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
    ) -> None:
        self.ws_socket = ws_socket
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        self.transport: Optional[paramiko.Transport] = None

    def start_ssh_transport(self) -> None:
        """Initialize Paramiko Transport over the raw ws_socket and authenticate."""
        self.transport = paramiko.Transport(self.ws_socket)
        self.transport.start_client()

        # You might want to do hostkey checks here, e.g.:
        # server_key = self.transport.get_remote_server_key()
        # if not verify_host_key(server_key):
        #     raise Exception("Unknown Host Key!")

        self.transport.auth_password(self.ssh_username, self.ssh_password)
        if not self.transport.is_authenticated():
            raise RuntimeError("SSH Authentication failed")

        logger.info("SSH transport established and authenticated.")

    def close(self) -> None:
        """Clean up the SSH transport."""
        if self.transport is not None:
            self.transport.close()

    def open_socks_proxy(self, local_port: int) -> None:
        """
        Start a SOCKS4/5 server on 127.0.0.1:local_port that forwards
        connections through the SSH transport.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", local_port))
        server.listen(100)
        logger.info("SOCKS proxy listening on 127.0.0.1:%d", local_port)

        def handle_socks_client(client_sock: socket.socket) -> None:
            try:
                initial = client_sock.recv(1, socket.MSG_PEEK)
                if not initial:
                    client_sock.close()
                    return

                ver = initial[0]
                if ver == 4:
                    self._handle_socks4(client_sock)
                elif ver == 5:
                    self._handle_socks5(client_sock)
                else:
                    logger.warning("Unsupported SOCKS version: %d", ver)
                    client_sock.close()

            except Exception as exc:
                logger.error("SOCKS client error: %s", exc)
                client_sock.close()

        def accept_loop() -> None:
            while True:
                try:
                    client_sock, _ = server.accept()
                    threading.Thread(
                        target=handle_socks_client,
                        args=(client_sock,),
                        daemon=True,
                    ).start()
                except OSError:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()
        logger.info("SOCKS proxy started.")

    def _forward_data(self, src: socket.socket, dst: socket.socket) -> None:
        """Forward data from src to dst until EOF, then close only src."""
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass

    def _open_ssh_channel(
        self, client_sock: socket.socket, host: str, port: int
    ) -> None:
        """Open a Paramiko direct-tcpip channel to (host, port) and relay data."""
        logger.debug("Opening SSH channel to %s:%d", host, port)
        chan = self.transport.open_channel(
            "direct-tcpip",
            (host, port),
            client_sock.getsockname(),
        )
        threading.Thread(
            target=self._forward_data, args=(client_sock, chan), daemon=True
        ).start()
        threading.Thread(
            target=self._forward_data, args=(chan, client_sock), daemon=True
        ).start()

    def _handle_socks4(self, client_sock: socket.socket) -> None:
        """Handle a SOCKS4 or SOCKS4a request."""
        # SOCKS4 layout:
        #   [0]   = 0x04 (version)
        #   [1]   = command (1=CONNECT)
        #   [2:4] = port (big-endian)
        #   [4:8] = IP (0.0.0.x means SOCKS4a)
        #   then null-terminated userID
        #   if SOCKS4a: null-terminated domain follows
        try:
            data = self._recv_all(client_sock)
            if len(data) < 9:
                client_sock.close()
                return

            cmd      = data[1]
            port     = struct.unpack(">H", data[2:4])[0]
            ip_part  = data[4:8]

            idx = 8
            while idx < len(data) and data[idx] != 0:
                idx += 1
            idx += 1  # skip null terminator of userID

            host = socket.inet_ntoa(ip_part)

            # SOCKS4a: IP is 0.0.0.x (x != 0) → domain follows userID
            if ip_part[:3] == b"\x00\x00\x00" and ip_part[3] != 0:
                domain_start = idx
                while idx < len(data) and data[idx] != 0:
                    idx += 1
                host = data[domain_start:idx].decode("utf-8", errors="replace")

            if cmd != 1:
                client_sock.sendall(_SOCKS4_REJECTED + b"\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            client_sock.sendall(_SOCKS4_GRANTED + data[2:4] + data[4:8])
            self._open_ssh_channel(client_sock, host, port)

        except Exception as exc:
            logger.error("SOCKS4 error: %s", exc)
            client_sock.close()

    def _handle_socks5(self, client_sock: socket.socket) -> None:
        """Handle a SOCKS5 request (no-auth only, CONNECT command)."""
        try:
            # Step 1: method negotiation
            ver_nmethods = client_sock.recv(2)
            if len(ver_nmethods) < 2:
                client_sock.close()
                return

            version, nmethods = ver_nmethods[0], ver_nmethods[1]
            if version != 5:
                client_sock.close()
                return

            client_sock.recv(nmethods)  # discard offered methods
            client_sock.sendall(_SOCKS5_NO_AUTH)

            # Step 2: connection request
            request_hdr = client_sock.recv(4)
            if len(request_hdr) < 4:
                client_sock.close()
                return

            _req_ver, cmd, _rsv, atyp = request_hdr

            if cmd != 0x01:
                self._send_socks5_error(client_sock, 0x07)  # command not supported
                return

            if atyp == 0x01:
                addr = client_sock.recv(4)
                host = socket.inet_ntoa(addr)
            elif atyp == 0x03:
                domain_len = client_sock.recv(1)[0]
                host = client_sock.recv(domain_len).decode("utf-8", errors="replace")
            elif atyp == 0x04:
                addr = client_sock.recv(16)
                host = socket.inet_ntop(socket.AF_INET6, addr)
            else:
                self._send_socks5_error(client_sock, 0x08)  # address type not supported
                return

            port_bytes = client_sock.recv(2)
            if len(port_bytes) < 2:
                client_sock.close()
                return
            port = struct.unpack(">H", port_bytes)[0]

            self._send_socks5_success(client_sock)
            self._open_ssh_channel(client_sock, host, port)

        except Exception as exc:
            logger.error("SOCKS5 error: %s", exc)
            client_sock.close()

    def _send_socks5_error(self, client_sock: socket.socket, err_code: int) -> None:
        """Send a SOCKS5 error reply and close the socket."""
        reply = b"\x05" + bytes([err_code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(reply)
        client_sock.close()

    def _send_socks5_success(self, client_sock: socket.socket) -> None:
        """Send a SOCKS5 connection-granted response."""
        client_sock.sendall(_SOCKS5_SUCCESS)

    def _recv_all(self, sock: socket.socket, timeout: float = 0.5) -> bytes:
        """Read all available bytes from sock with a short timeout."""
        sock.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
            except Exception:
                break
        sock.settimeout(None)
        return data


def connect_via_ws_and_start_socks(
    ws_socket: socket.socket,
    ssh_user: str,
    ssh_password: str,
    ssh_port: int,
    local_socks_port: int,
) -> SSHOverWebSocket:
    """Start SSH transport over ws_socket and open a local SOCKS proxy."""
    connector = SSHOverWebSocket(ws_socket, ssh_user, ssh_password, ssh_port)
    connector.start_ssh_transport()
    connector.open_socks_proxy(local_socks_port)
    return connector
