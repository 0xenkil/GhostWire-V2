"""Phase 5 — P5-2 config consolidation (D-DEL-2 / D-CONFIG-1).

Three overlapping config modules collapsed to ONE `core.config_loader`:
  - `core/config_manager.py` (the misnamed MockConfig) is retired; its
    `.timeout` / `.vps` attribute views now live on `ConfigManager`.
  - `core/unified_config_loader.py` (zero importers) is deleted.
  - The clashing no-arg `config_manager.get_config` is gone; `get_config_manager`
    is the single entry, with precedence env > YAML > module default.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_loader import ConfigManager, get_config, get_config_manager  # noqa: E402


def test_manager_exposes_timeout_and_vps_views():
    cfg = get_config_manager()
    assert isinstance(cfg, ConfigManager)
    # The views MockConfig used to serve now hang off the one manager.
    assert isinstance(cfg.timeout.tool_default, int)
    assert isinstance(cfg.timeout.tool_verify, int)
    assert isinstance(cfg.vps.use_remote_vps, bool)


def test_timeout_view_defaults_match_retired_mockconfig():
    # config.py does not define these three, so they resolve to the module
    # default exactly as MockConfig's getattr fallback did — no silent change.
    t = get_config_manager().timeout
    assert t.tool_default == 300
    assert t.tool_verify == 30
    assert t.rate_limit_max_backoff == 60


def test_missing_timeout_attr_falls_to_getattr_default():
    # capability_registry relies on getattr(_config.timeout, 'tool_install_check', 30).
    t = get_config_manager().timeout
    assert getattr(t, "tool_install_check", 30) == 30
    assert not hasattr(t, "tool_install_check")


def test_get_config_manager_is_singleton():
    assert get_config_manager() is get_config_manager()


def test_precedence_env_beats_default_and_casts_type():
    # env > (YAML absent) > default, cast to the default's type.
    key = "P5_CONSOLIDATION_PROBE_ENV"
    os.environ[key] = "42"
    try:
        val = get_config("general", "nonexistent.deeply.nested.key", 999, key)
        assert val == 42 and isinstance(val, int)
    finally:
        del os.environ[key]


def test_precedence_falls_to_default_when_absent_everywhere():
    val = get_config("general", "nonexistent.deeply.nested.key", 7,
                     "P5_DEFINITELY_UNSET_ENV_VAR")
    assert val == 7


@pytest.mark.parametrize("mod", [
    "core.config_manager",
    "core.unified_config_loader",
])
def test_retired_config_modules_are_gone(mod):
    # Includes the sourceless-.pyc shadow check: a leftover core/config_manager.pyc
    # kept the module importable after the source was deleted (caught in review).
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(mod)
