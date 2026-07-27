import http.server
import socketserver
import urllib.request
import urllib.error
import threading
import logging
from core.waf_ghost_engine import WafGhostEngine
from config import PROXY_PORT

log = logging.getLogger("stealth_proxy")


class StealthProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.proxy_request('GET')

    def do_POST(self):
        self.proxy_request('POST')

    def proxy_request(self, method):
        url = self.path

        # Determine target host
        # The URL comes in as http://target.com/path
        if not url.startswith('http'):
            self.send_error(400, "Bad Request: URL must be absolute")
            return

        # FIX P0-5: Block SSRF to local/private/link-local networks
        import ipaddress
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                # Resolve hostname to check IP
                import socket
                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(socket.gethostbyname, hostname)
                        ip = future.result(timeout=15)
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        log.warning(
                            f"Blocked SSRF attempt to internal/private IP: {ip} for host {hostname}")
                        self.send_error(
                            403, "Forbidden: Access to internal networks is blocked")
                        return
                except socket.gaierror:
                    # DNS resolution failed, we'll let it fail naturally or
                    # block if it's a raw IP
                    pass
                except concurrent.futures.TimeoutError:
                    log.warning(f"DNS resolution for {hostname} timed out, skipping SSRF check.")
                    pass
        except Exception as e:
            log.error(f"Error parsing URL or checking IP for SSRF: {e}")
            self.send_error(400, "Bad Request: Invalid URL format")
            return

        # Get Stealth Headers from WafGhostEngine
        waf_engine = WafGhostEngine()
        stealth_headers = waf_engine._generate_stealth_headers()

        # Build request
        req = urllib.request.Request(url, method=method)

        # Forward original headers, overlaid with stealth headers
        for k, v in self.headers.items():
            if k.lower() not in ['host', 'connection', 'user-agent', 'accept']:
                req.add_header(k, v)
        for k, v in stealth_headers.items():
            req.add_header(k, v)

        # Forward body if POST
        if method == 'POST':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                req.data = self.rfile.read(content_length)

        try:
            # We would add proxy rotation here using
            # urllib.request.ProxyHandler if configured
            with urllib.request.urlopen(req, timeout=15) as response:
                self.send_response(response.status)
                for k, v in response.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            log.error(f"Proxy request failed: {e}")
            self.send_error(502, f"Bad Gateway: {e}")


class StealthProxy:
    def __init__(self, port=PROXY_PORT):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        if self.server:
            return
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(
            ("", self.port), StealthProxyHandler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        log.info(f"Stealth Proxy started on port {self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            log.info("Stealth Proxy stopped")
