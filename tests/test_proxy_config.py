from __future__ import annotations

from types import SimpleNamespace

from lib import config
from lib.config import RuntimeConfig, resolve_proxy


def _clear_proxy_env(monkeypatch):
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


def test_resolve_proxy_prefers_explicit_value(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setattr(config.urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:20122"})

    assert resolve_proxy("127.0.0.1:9000") == "http://127.0.0.1:9000"


def test_resolve_proxy_can_be_disabled(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setattr(config.urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:20122"})

    assert resolve_proxy("", no_proxy=True) == ""


def test_runtime_config_uses_system_proxy_when_env_is_missing(monkeypatch, tmp_path):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setattr(config, "load_dotenv", lambda *args, **kwargs: {})
    monkeypatch.setattr(config.urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:20122"})
    args = SimpleNamespace(
        artifact_dir=str(tmp_path),
        export_targets="none",
        no_sub2api=False,
        proxy=None,
        no_proxy=False,
    )

    cfg = RuntimeConfig.from_env_and_args(args)

    assert cfg.proxy == "http://127.0.0.1:20122"
