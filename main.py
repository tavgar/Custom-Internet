import logging
import time

from config import CONFIG, validate_config
from tunnel_strategies import get_strategy
from ssh_connector import connect_via_ws_and_start_socks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> None:
    """
    1) Validate config.
    2) Use the chosen strategy to do the WebSocket handshake.
    3) Wrap the socket in Paramiko's SSH transport.
    4) Expose a local SOCKS proxy on CONFIG['LOCAL_SOCKS_PORT'].
    5) Block until the user kills the process.
    """
    try:
        validate_config(CONFIG)

        strategy_cls = get_strategy(CONFIG["MODE"])
        ws_sock = strategy_cls(CONFIG).establish()

        ssh_connection = connect_via_ws_and_start_socks(
            ws_socket=ws_sock,
            ssh_user=CONFIG["SSH_USERNAME"],
            ssh_password=CONFIG["SSH_PASSWORD"],
            ssh_port=CONFIG["SSH_PORT"],
            local_socks_port=CONFIG["LOCAL_SOCKS_PORT"],
        )

        logger.info(
            "SOCKS proxy up on 127.0.0.1:%d – all traffic forwarded over SSH via WS tunnel.",
            CONFIG["LOCAL_SOCKS_PORT"],
        )

        while True:
            time.sleep(999999)

    except KeyboardInterrupt:
        logger.info("Shutting down (KeyboardInterrupt).")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)


if __name__ == "__main__":
    main()
