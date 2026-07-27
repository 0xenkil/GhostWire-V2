import unittest
from core.c2_simulator import BeaconProfile


class TestC2Simulator(unittest.TestCase):
    def test_default_profile_headers(self):
        profile = BeaconProfile("default")
        self.assertIn("Accept", profile.headers)
        self.assertIn("Accept-Language", profile.headers)

    def test_smuggle_image_profile(self):
        profile = BeaconProfile("smuggle_image")
        self.assertIn("image/webp", profile.headers["Accept"])

    def test_jitter_calculation(self):
        profile = BeaconProfile("default")
        # base_sleep is 10, jitter is 20%, so sleep should be between 8 and 12
        for _ in range(100):
            sleep = profile.get_sleep_time()
            self.assertGreaterEqual(sleep, 8.0)
            self.assertLessEqual(sleep, 12.0)

    def test_format_request(self):
        profile = BeaconProfile("default")
        payload = b"id"
        req = profile.format_request(payload)

        self.assertEqual(req["method"], "GET")
        self.assertTrue(req["uri"] in profile.uri_paths)
        self.assertIn("X-Session-Token", req["headers"])

        import base64
        decoded = base64.b64decode(req["headers"]["X-Session-Token"])
        self.assertEqual(decoded, payload)


if __name__ == "__main__":
    unittest.main()
