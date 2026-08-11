"""Stealth must route DNS THROUGH Tor: proxychains needs socks5 + remote DNS.

The system /etc/proxychains4.conf commonly ships as socks4, which resolves target
hostnames LOCALLY — leaking DNS and failing HTTPS to hosts whose locally-resolved
IP refuses the Tor exit (observed live as 'tlsv1 alert internal error' /
'connection refused' on real targets). IpRotator now writes a user-level
~/.proxychains/proxychains.conf with socks5 + proxy_dns (precedence over /etc,
no root), so proxied tools reach targets through Tor.
"""
from core.ip_rotator import IpRotator
from config_backends import TOR_SOCKS_PORT


class _Exec:
    def __init__(self):
        self.cmd = ""

    def execute(self, cmd, timeout=10):
        self.cmd = cmd
        return (0, "", "")


def _rotator(exec_obj=None):
    # _socks_port is a fixed property (TOR_SOCKS_PORT); only _ssh needs setting.
    r = IpRotator.__new__(IpRotator)
    r._ssh = exec_obj or _Exec()
    return r


def test_writes_socks5_remote_dns_config():
    r = _rotator()
    r._ensure_proxychains_config()
    cmd = r._ssh.cmd
    assert f"socks5 127.0.0.1 {TOR_SOCKS_PORT}" in cmd    # socks5, not socks4
    assert "socks4" not in cmd
    assert "proxy_dns" in cmd                             # DNS resolved through Tor
    assert "~/.proxychains/proxychains.conf" in cmd       # user-level, no root


def test_write_failure_is_non_fatal():
    class _Boom:
        def execute(self, *a, **k):
            raise RuntimeError("no wsl")
    r = _rotator(_Boom())
    r._ensure_proxychains_config()                        # must not raise
