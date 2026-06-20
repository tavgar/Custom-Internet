import pytest
from unittest.mock import MagicMock, patch

from tunnel_strategies import (
    get_strategy,
    DirectStrategy,
    HttpPayloadStrategy,
    SNIFrontedStrategy,
)


def _base_cfg(**overrides):
    cfg = {
        "PROXY_HOST": "proxy.ex",
        "PROXY_PORT": 80,
        "TARGET_HOST": "target.ex",
        "TARGET_PORT": 22,
        "PAYLOAD_TEMPLATE": "GET /[crlf]Host: [host][crlf][crlf]",
        "FRONT_DOMAIN": "",
    }
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# get_strategy factory
# ---------------------------------------------------------------------------

class TestGetStrategy:
    @pytest.mark.parametrize(
        "mode,expected",
        [
            ("direct", DirectStrategy),
            ("http_payload", HttpPayloadStrategy),
            ("sni_fronted", SNIFrontedStrategy),
        ],
    )
    def test_valid_modes_return_correct_class(self, mode, expected):
        assert get_strategy(mode) is expected

    @pytest.mark.parametrize("mode", ["DIRECT", "HTTP_PAYLOAD", "SNI_FRONTED"])
    def test_case_insensitive(self, mode):
        assert get_strategy(mode) is not None

    def test_unknown_mode_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown MODE"):
            get_strategy("bogus_mode")

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            get_strategy("")


# ---------------------------------------------------------------------------
# DirectStrategy
# ---------------------------------------------------------------------------

class TestDirectStrategy:
    @patch("tunnel_strategies.socket.create_connection")
    def test_establish_connects_to_target(self, mock_conn):
        fake_sock = MagicMock()
        mock_conn.return_value = fake_sock
        cfg = _base_cfg(TARGET_HOST="myhost.net", TARGET_PORT=2222)

        result = DirectStrategy(cfg).establish()

        mock_conn.assert_called_once_with(("myhost.net", 2222))
        assert result is fake_sock


# ---------------------------------------------------------------------------
# HttpPayloadStrategy
# ---------------------------------------------------------------------------

class TestHttpPayloadStrategy:
    @patch("tunnel_strategies.establish_ws_tunnel")
    def test_establish_calls_ws_tunnel_with_correct_kwargs(self, mock_est):
        fake_sock = MagicMock()
        mock_est.return_value = fake_sock
        cfg = _base_cfg()

        result = HttpPayloadStrategy(cfg).establish()

        mock_est.assert_called_once_with(
            proxy_host="proxy.ex",
            proxy_port=80,
            target_host="target.ex",
            target_port=22,
            payload_template=cfg["PAYLOAD_TEMPLATE"],
            use_tls=False,
        )
        assert result is fake_sock


# ---------------------------------------------------------------------------
# SNIFrontedStrategy
# ---------------------------------------------------------------------------

class TestSNIFrontedStrategy:
    @patch("tunnel_strategies.establish_ws_tunnel")
    @patch("tunnel_strategies.ssl.create_default_context")
    @patch("tunnel_strategies.socket.create_connection")
    def test_uses_front_domain_as_sni(self, mock_conn, mock_ctx, mock_est):
        raw_sock = MagicMock()
        tls_sock = MagicMock()
        mock_conn.return_value = raw_sock
        mock_ctx.return_value.wrap_socket.return_value = tls_sock
        mock_est.return_value = tls_sock
        cfg = _base_cfg(PROXY_PORT=443, FRONT_DOMAIN="cdn.example.com")

        result = SNIFrontedStrategy(cfg).establish()

        mock_ctx.return_value.wrap_socket.assert_called_once_with(
            raw_sock, server_hostname="cdn.example.com"
        )
        mock_est.assert_called_once_with(
            proxy_host="proxy.ex",
            proxy_port=443,
            target_host="target.ex",
            target_port=22,
            payload_template=cfg["PAYLOAD_TEMPLATE"],
            sock=tls_sock,
            use_tls=False,
        )
        assert result is tls_sock

    @patch("tunnel_strategies.establish_ws_tunnel")
    @patch("tunnel_strategies.ssl.create_default_context")
    @patch("tunnel_strategies.socket.create_connection")
    def test_falls_back_to_proxy_host_when_no_front_domain(
        self, mock_conn, mock_ctx, mock_est
    ):
        raw_sock = MagicMock()
        tls_sock = MagicMock()
        mock_conn.return_value = raw_sock
        mock_ctx.return_value.wrap_socket.return_value = tls_sock
        mock_est.return_value = tls_sock
        cfg = _base_cfg(FRONT_DOMAIN="")  # empty → fall back to PROXY_HOST

        SNIFrontedStrategy(cfg).establish()

        mock_ctx.return_value.wrap_socket.assert_called_once_with(
            raw_sock, server_hostname="proxy.ex"
        )
