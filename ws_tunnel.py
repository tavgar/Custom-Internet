from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#                               Helper utilities                              #
# --------------------------------------------------------------------------- #
def replace_placeholders(payload: str, target_host: str, target_port: int) -> bytes:
    """
    Swap **[host]** ➜ “target_host:target_port” and **[crlf]** ➜ “\\r\\n”
    inside *payload*.
    """
    host_value = f"{target_host}:{target_port}"
    payload = payload.replace("[host]", host_value).replace("[crlf]", "\r\n")
    return payload.encode()


def read_headers(sock: socket.socket) -> bytes:
    """
    Read from *sock* until a blank line (\\r\\n\\r\\n) is reached and return
    the full header block (including the delimiter).
    """
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


# --------------------------------------------------------------------------- #
#                              Public entry point                              #
# --------------------------------------------------------------------------- #
def establish_ws_tunnel(
    *,
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    payload_template: str,
    use_tls: bool = False,
    sock: Optional[socket.socket] = None,
) -> socket.socket:
    """
    Perform the upgrade handshake and return a ready-for-SSH socket.

    Parameters
    ----------
    proxy_host / proxy_port
        TCP endpoint we dial *first* (often 80 or 443 on a CDN edge).
    target_host / target_port
        Host:port ultimately placed in the Host header via `[host]`.
    payload_template
        One or more HTTP request blocks separated by blank lines, using the
        placeholders above.
    use_tls
        If *True* a new connection is wrapped in TLS with SNI = proxy_host.
        Ignored if *sock* is already provided.
    sock
        A *pre-connected* socket (possibly already TLS-wrapped).  This is how
        SNI-fronted or custom transports inject their own socket.

    Notes
    -----
    • The function is idempotent w.r.t. TLS – if `sock` is already an
      `ssl.SSLSocket`, a second wrap is skipped even if `use_tls=True`.
    • Caller owns lifecycle: close `sock` yourself when finished.
    """
    # ------------------------------------------------------------------ #
    # 1. Connect or re-use an existing socket
    # ------------------------------------------------------------------ #
    if sock is None:
        sock = socket.create_connection((proxy_host, proxy_port))

    # Optional TLS upgrade (skip if it’s already SSL)
    if use_tls and not isinstance(sock, ssl.SSLSocket):
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=proxy_host)

    # ------------------------------------------------------------------ #
    # 2. Build payload blocks
    # ------------------------------------------------------------------ #
    payload_bytes = replace_placeholders(payload_template, target_host, target_port)
    blocks = payload_bytes.split(b"\r\n\r\n")

    # ------------------------------------------------------------------ #
    # 3. Send first block
    # ------------------------------------------------------------------ #
    sock.sendall(blocks[0] + b"\r\n\r\n")

    # ------------------------------------------------------------------ #
    # 4. Read first response
    # ------------------------------------------------------------------ #
    first = read_headers(sock)
    logger.debug("First response: %s", first.decode("latin1", errors="replace"))

    # ------------------------------------------------------------------ #
    # 5. If 100-Continue, send remaining blocks, else send them anyway
    # ------------------------------------------------------------------ #
    if b"100 Continue" in first:
        for blk in blocks[1:]:
            if blk.strip():
                sock.sendall(blk + b"\r\n\r\n")
        second = read_headers(sock)
        label = "Second response"
    else:
        # Some servers skip 100-Continue; we still must flush any extras.
        if len(blocks) > 1:
            for blk in blocks[1:]:
                if blk.strip():
                    sock.sendall(blk + b"\r\n\r\n")
        second = read_headers(sock)
        label = "Second response (no 100-Continue path)"

    logger.debug("%s: %s", label, second.decode("latin1", errors="replace"))

    # ------------------------------------------------------------------ #
    # 6. Tunnel is live
    # ------------------------------------------------------------------ #
    logger.info("WebSocket handshake complete – tunnel is live.")
    return sock