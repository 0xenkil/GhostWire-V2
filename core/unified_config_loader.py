import os
from pathlib import Path


class UnifiedConfigLoader:
    """Centralizes configuration management for Ghostwire."""

    def __init__(self, config_dir: str = None):
        if not config_dir:
            config_dir = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
        self.config_dir = Path(config_dir)
        self.config = {}
        self._load_all()

    def _load_all(self):
        # Merge old discrete configs into a single namespace for the session
        try:
            import config
            self.config['USE_REMOTE_VPS'] = getattr(
                config, 'USE_REMOTE_VPS', False)
            self.config['USE_WSL'] = getattr(config, 'USE_WSL', True)
            self.config['VPS_DISK_ABORT_PCT'] = getattr(
                config, 'VPS_DISK_ABORT_PCT', 95)
        except ImportError:
            pass

        try:
            import config_paths
            self.config['LOG_DIR'] = getattr(
                config_paths, 'LOG_DIR', self.config_dir / 'logs')
            self.config['WORDLIST_DIR'] = getattr(
                config_paths, 'WORDLIST_DIR', self.config_dir / 'wordlists')
        except ImportError:
            pass

        try:
            import config_thresholds
            self.config['VPS_HEALTH_CHECK_TIMEOUT'] = getattr(
                config_thresholds, 'VPS_HEALTH_CHECK_TIMEOUT', 10)
        except ImportError:
            pass

        try:
            import config_backends
            self.config['AI_BACKENDS'] = getattr(
                config_backends, 'AI_BACKENDS', {})
        except ImportError:
            pass

    def get(self, key: str, default=None):
        return self.config.get(key, default)
