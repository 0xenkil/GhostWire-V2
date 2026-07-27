import config


class MockTimeoutConfig:
    @property
    def rate_limit_initial_backoff(self): return getattr(
        config, 'RATE_LIMIT_INITIAL_BACKOFF', 10)

    @property
    def rate_limit_max_backoff(self): return getattr(
        config, 'RATE_LIMIT_MAX_BACKOFF', 60)

    @property
    def tool_default(self): return getattr(config, 'TOOL_DEFAULT_TIMEOUT', 300)
    @property
    def tool_verify(self): return getattr(config, 'TOOL_VERIFY_TIMEOUT', 30)


class MockVpsConfig:
    @property
    def use_remote_vps(self): return getattr(config, 'USE_REMOTE_VPS', False)


class MockConfig:
    def __init__(self):
        self.timeout = MockTimeoutConfig()
        self.vps = MockVpsConfig()


def get_config():
    return MockConfig()


__all__ = ["get_config"]
