import base64
import random


class BeaconProfile:
    def __init__(self, name: str):
        self.name = name
        self.headers = {
            "Accept": "*/*" if name == "default" else "image/webp",
            "Accept-Language": "en-US",
        }
        self.uri_paths = ["/"]

    def get_sleep_time(self) -> float:
        # base_sleep = 10, jitter = 20%
        return 10.0 + random.uniform(-2.0, 2.0)

    def format_request(self, payload: bytes) -> dict:
        return {
            "method": "GET",
            "uri": "/",
            "headers": {
                **self.headers,
                "X-Session-Token": base64.b64encode(payload).decode("utf-8")
            }
        }
