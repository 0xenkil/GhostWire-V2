import unittest
import time
from core.stealth_proxy import StealthProxy


class TestStealthProxy(unittest.TestCase):
    def setUp(self):
        self.proxy = StealthProxy(port=8081)
        self.proxy.start()
        time.sleep(0.5)

    def tearDown(self):
        self.proxy.stop()

    def test_proxy_headers(self):
        self.assertTrue(self.proxy.thread.is_alive())


if __name__ == '__main__':
    unittest.main()
