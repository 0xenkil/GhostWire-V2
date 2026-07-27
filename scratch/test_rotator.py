from core.ip_rotator import IpRotator
import sys
sys.path.append('.')


class MockExecutor:
    def execute(self, cmd, timeout=10):
        if "ss -tlnp" in cmd or "nc -z" in cmd:
            return 0, "SOCKS_OK", ""
        if "curl" in cmd:
            return 1, "", "timeout"
        return 0, "", ""


rotator = IpRotator(MockExecutor(), rules={})
print("ensure_tor_ready():", rotator.ensure_tor_ready())
print("is disabled:", getattr(rotator, '_tor_disabled', False))
print("wrapped command:", rotator.build_proxychains_cmd(
    "subfinder -d novalink.lk -silent"))
