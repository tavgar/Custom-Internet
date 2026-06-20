import pytest
from config import validate_config


def _valid_cfg():
    return {
        "PROXY_HOST": "proxy.example.com",
        "PROXY_PORT": 80,
        "TARGET_HOST": "target.example.com",
        "TARGET_PORT": 80,
        "SSH_USERNAME": "user",
        "SSH_PASSWORD": "pass",
        "SSH_PORT": 22,
    }


def test_valid_config_passes():
    validate_config(_valid_cfg())  # must not raise


@pytest.mark.parametrize("field", ["PROXY_HOST", "TARGET_HOST", "SSH_USERNAME", "SSH_PASSWORD"])
def test_empty_string_field_raises(field):
    cfg = _valid_cfg()
    cfg[field] = ""
    with pytest.raises(ValueError, match=field):
        validate_config(cfg)


@pytest.mark.parametrize("field", ["PROXY_PORT", "TARGET_PORT", "SSH_PORT"])
def test_zero_port_raises(field):
    cfg = _valid_cfg()
    cfg[field] = 0
    with pytest.raises(ValueError, match=field):
        validate_config(cfg)


@pytest.mark.parametrize("field", ["PROXY_HOST", "TARGET_HOST", "SSH_USERNAME", "SSH_PASSWORD"])
def test_missing_key_raises(field):
    cfg = _valid_cfg()
    del cfg[field]
    with pytest.raises(ValueError, match=field):
        validate_config(cfg)
