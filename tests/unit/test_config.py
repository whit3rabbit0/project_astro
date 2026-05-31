import os

import pytest
from pydantic import ValidationError

from astro.server.config import AstroConfig, load_config


class TestAstroConfigDefaults:
    def test_default_host(self):
        config = AstroConfig()
        assert config.host == "127.0.0.1"

    def test_default_port(self):
        config = AstroConfig()
        assert config.port == 8080

    def test_default_transport(self):
        config = AstroConfig()
        assert config.transport == "streamable-http"

    def test_default_scope_config_path_is_none(self):
        config = AstroConfig()
        assert config.scope_config_path is None

    def test_default_debug_is_false(self):
        config = AstroConfig()
        assert config.debug is False

    def test_default_db_path(self):
        config = AstroConfig()
        assert config.db_path == "~/.astro/engagements.db"

    def test_default_api_key_is_none(self):
        config = AstroConfig()
        assert config.api_key is None


class TestAstroConfigValidation:
    def test_port_minimum_is_1(self):
        with pytest.raises(ValidationError):
            AstroConfig(port=0)

    def test_port_maximum_is_65535(self):
        with pytest.raises(ValidationError):
            AstroConfig(port=65536)

    def test_valid_port_boundaries(self):
        config_low = AstroConfig(port=1)
        assert config_low.port == 1
        config_high = AstroConfig(port=65535)
        assert config_high.port == 65535

    def test_negative_port_rejected(self):
        with pytest.raises(ValidationError):
            AstroConfig(port=-1)


class TestLoadConfig:
    def test_loads_defaults_without_env_vars(self, monkeypatch):
        for var in ["ASTRO_HOST", "ASTRO_PORT", "ASTRO_TRANSPORT",
                     "ASTRO_SCOPE_CONFIG", "ASTRO_DEBUG", "ASTRO_DB_PATH", "API_KEY"]:
            monkeypatch.delenv(var, raising=False)
        config = load_config()
        assert config.host == "127.0.0.1"
        assert config.port == 8080

    def test_host_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_HOST", "0.0.0.0")
        config = load_config()
        assert config.host == "0.0.0.0"

    def test_port_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_PORT", "9090")
        config = load_config()
        assert config.port == 9090

    def test_transport_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_TRANSPORT", "stdio")
        config = load_config()
        assert config.transport == "stdio"

    def test_debug_true_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_DEBUG", "true")
        config = load_config()
        assert config.debug is True

    def test_debug_yes_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_DEBUG", "yes")
        config = load_config()
        assert config.debug is True

    def test_debug_1_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_DEBUG", "1")
        config = load_config()
        assert config.debug is True

    def test_debug_false_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_DEBUG", "0")
        config = load_config()
        assert config.debug is False

    def test_db_path_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_DB_PATH", "/tmp/test.db")
        config = load_config()
        assert config.db_path == "/tmp/test.db"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "secret-key-123")
        config = load_config()
        assert config.api_key == "secret-key-123"

    def test_scope_config_from_env(self, monkeypatch):
        monkeypatch.setenv("ASTRO_SCOPE_CONFIG", "/etc/astro/scope.yaml")
        config = load_config()
        assert config.scope_config_path == "/etc/astro/scope.yaml"

    def test_empty_scope_config_becomes_none(self, monkeypatch):
        monkeypatch.setenv("ASTRO_SCOPE_CONFIG", "")
        config = load_config()
        assert config.scope_config_path is None

    def test_empty_api_key_becomes_none(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "")
        config = load_config()
        assert config.api_key is None
