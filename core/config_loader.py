import yaml
import os
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv
from typing import Any, Optional

load_dotenv()


@lru_cache(maxsize=32)
def load_yaml_config(config_name: str) -> dict:
    """
    Loads a YAML configuration file from the config directory.
    Result is cached.
    """
    base_dir = Path(__file__).parent.parent

    # Prevent path traversal by ensuring config_name contains only safe
    # characters
    import re
    safe_config_name = re.sub(r'[^A-Za-z0-9_-]', '', config_name)[:64]
    if not safe_config_name:
        return {}

    config_path = base_dir / "config" / f"{safe_config_name}.yaml"

    if not config_path.exists():
        return {}

    with open(config_path, "r") as f:
        try:
            return yaml.safe_load(f) or {}
        except yaml.YAMLError:
            return {}


def get_config(config_name: str, key_path: str,
               default=None, env_var: str = None):
    """
    Retrieves a configuration value from a YAML file with optional environment variable override.

    key_path: dot-separated path to the value in YAML (e.g., 'ai_backends.ollama.timeout')
    env_var: name of the environment variable that can override this value.
    """
    if env_var and env_var in os.environ:
        val = os.environ[env_var]
        # Try to cast to same type as default if provided
        if default is not None:
            try:
                if isinstance(default, bool):
                    return val.lower() in ("true", "1", "yes")
                return type(default)(val)
            except (ValueError, TypeError):
                return val
        return val

    config = load_yaml_config(config_name)
    parts = key_path.split(".")
    val = config
    for part in parts:
        if isinstance(val, dict) and part in val:
            val = val[part]
        else:
            return default
    return val


# ── P5-2 (D-CONFIG-1): attribute views over the `config` module ──────────────
# These replace core/config_manager.py's MockTimeoutConfig / MockVpsConfig /
# MockConfig VERBATIM (deleted) so the consolidated ConfigManager is the ONE
# config authority. `config` is imported LAZILY inside each property because
# config.py imports THIS module at top level — a module-level import here would
# be a cycle. Precedence is env > YAML > module default: the `config` module
# constants already resolve env>YAML>default (via get_config()); the getattr
# fallback is the final module default. NOTE (unchanged from MockConfig):
# config.py does not define TOOL_DEFAULT_TIMEOUT / TOOL_VERIFY_TIMEOUT /
# RATE_LIMIT_MAX_BACKOFF, so those resolve to the getattr defaults today.
class _TimeoutView:
    @property
    def rate_limit_initial_backoff(self):
        import config
        return getattr(config, "RATE_LIMIT_INITIAL_BACKOFF", 10)

    @property
    def rate_limit_max_backoff(self):
        import config
        return getattr(config, "RATE_LIMIT_MAX_BACKOFF", 60)

    @property
    def tool_default(self):
        import config
        return getattr(config, "TOOL_DEFAULT_TIMEOUT", 300)

    @property
    def tool_verify(self):
        import config
        return getattr(config, "TOOL_VERIFY_TIMEOUT", 30)


class _VpsView:
    @property
    def use_remote_vps(self):
        import config
        return getattr(config, "USE_REMOTE_VPS", False)


class ConfigManager:
    """
    FIX #4.1: Unified configuration manager that centralizes all config access.
    Provides backward compatibility while consolidating config files.
    Supports loading from environment variables, YAML files, and Python modules.

    P5-2: also exposes the `.timeout` / `.vps` attribute views formerly served by
    the retired core.config_manager.MockConfig, so `get_config().vps.use_remote_vps`
    and `get_config().timeout.tool_default` route through this single manager.
    """

    def __init__(self):
        self._backends_config = None
        self._paths_config = None
        self._thresholds_config = None
        self._general_config = None
        self._tools_config = None

    @property
    def timeout(self) -> _TimeoutView:
        return _TimeoutView()

    @property
    def vps(self) -> _VpsView:
        return _VpsView()

    def _load_backends_config(self) -> dict:
        """Load AI backends and external service credentials."""
        if self._backends_config is None:
            self._backends_config = load_yaml_config("backends")
        return self._backends_config

    def _load_paths_config(self) -> dict:
        """Load filesystem paths."""
        if self._paths_config is None:
            self._paths_config = load_yaml_config("paths")
        return self._paths_config

    def _load_thresholds_config(self) -> dict:
        """Load timeouts and thresholds."""
        if self._thresholds_config is None:
            self._thresholds_config = load_yaml_config("thresholds")
        return self._thresholds_config

    def _load_general_config(self) -> dict:
        """Load general settings."""
        if self._general_config is None:
            self._general_config = load_yaml_config("general")
        return self._general_config

    def _load_tools_config(self) -> dict:
        """Load tools settings."""
        if self._tools_config is None:
            self._tools_config = load_yaml_config("tools")
        return self._tools_config

    def get(self, key: str, default: Any = None,
            env_var: Optional[str] = None) -> Any:
        """
        Get a configuration value by key.
        Supports dot notation: 'backends.groq.api_key' or 'paths.wordlist_dir'
        FIX #4.1: Single entry point for all config access.
        """
        # Environment variable takes precedence
        if env_var and env_var in os.environ:
            val = os.environ[env_var]
            if default is not None and isinstance(default, bool):
                return val.lower() in ("true", "1", "yes")
            if default is not None:
                try:
                    return type(default)(val)
                except (ValueError, TypeError):
                    return val
            return val

        # Try each config source in order
        parts = key.split(".")
        if len(parts) < 2:
            return default

        section = parts[0]
        subkey = ".".join(parts[1:])

        if section == "backends":
            config = self._load_backends_config()
        elif section == "paths":
            config = self._load_paths_config()
        elif section == "thresholds":
            config = self._load_thresholds_config()
        elif section == "tools":
            config = self._load_tools_config()
        else:
            config = self._load_general_config()

        # Navigate nested dict with dot notation
        val = config
        for part in subkey.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                return default

        return val

    def get_int(self, key: str, default: int = 0) -> int:
        """Get config value as integer."""
        val = self.get(key, default)
        try:
            return int(val) if val is not None else default
        except (ValueError, TypeError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get config value as boolean."""
        val = self.get(key, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower() in ("true", "1", "yes", "on")
        return bool(val) if val is not None else default

    def get_str(self, key: str, default: str = "") -> str:
        """Get config value as string."""
        val = self.get(key, default)
        return str(val) if val is not None else default


# Singleton instance for easy access
_config_manager = None


def get_config_manager() -> ConfigManager:
    """Get or create the singleton ConfigManager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def reset_config_cache():
    """Clear cached configs (useful for testing)."""
    global _config_manager
    _config_manager = None
    load_yaml_config.cache_clear()
