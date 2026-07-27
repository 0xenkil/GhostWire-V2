"""
tripwire_detector.py - Ghostwire Tripwire & Honeypot Detector
"""
import socket
from typing import List
from utils.logger import get_logger
from config_thresholds import HONEYPOT_PORT_THRESHOLD, HONEYPOT_RESPONSE_SIMILARITY_THRESHOLD

log = get_logger("tripwire_detector")


class TripwireDetector:
    def __init__(self, remote_executor=None):
        self.ssh = remote_executor

    def is_honeypot_active(self, ports: List[int]) -> bool:
        """
        Check if the port density is unusually high, indicating an active defense honeypot (e.g. Portspoof).
        """
        if not ports:
            return False

        density = len(ports)
        if density >= HONEYPOT_PORT_THRESHOLD:
            log.warning(
                f"[TRIPWIRE DETECTOR] Alert: Port density critical. "
                f"Discovered {density} open ports on target. Threshold limit: {HONEYPOT_PORT_THRESHOLD}."
            )
            return True
        return False

    def check_banner_similarity(self, host: str, ports: List[int]) -> bool:
        """
        Probe a subset of open ports to analyze banner signatures.
        If different ports return identical or highly similar mock banner sizes/contents,
        then it is classified as a honeypot.
        """
        if len(ports) < 5:
            return False

        # Select a random sample of 5 ports (excluding standard 80/443 web
        # channels if possible)
        test_ports = [p for p in ports if p not in (80, 443, 22)]
        if len(test_ports) < 5:
            test_ports = ports[:5]
        else:
            import random
            test_ports = random.sample(test_ports, min(5, len(test_ports)))

        banners = {}
        for port in test_ports:
            try:
                banner = self._grab_raw_banner(host, port)
                if banner:
                    banners[port] = banner
            except Exception as e:
                log.debug(f"Banner grab failed on {host}:{port} - {e}")

        if len(banners) < 3:
            return False  # Not enough data to calculate similarity safely

        # Calculate similarity across returned banners
        samples = list(banners.values())
        matching_count = 0
        total_comparisons = 0

        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                total_comparisons += 1
                sim = self._calculate_jaccard_similarity(
                    samples[i], samples[j])
                if sim >= HONEYPOT_RESPONSE_SIMILARITY_THRESHOLD:
                    matching_count += 1

        if total_comparisons > 0:
            matching_ratio = matching_count / total_comparisons
            if matching_ratio >= 0.75:
                log.warning(
                    f"[TRIPWIRE DETECTOR] Alert: Host banner similarity triggers active defense! "
                    f"Ratio: {
                        matching_ratio:.1%} identical signatures across {
                        len(banners)} checked ports."
                )
                return True
        return False

    def prune_honeypot_ports(self, host: str,
                             raw_ports: List[int]) -> List[int]:
        """
        Active Honeypot/Tripwire Bypass Strategy:
        Strip all fake ports, and return only confirmed live, standardized web channels
        (80, 443, 8080, 8443) that respond to legitimate HTTP requests.
        """
        log.info(
            f"[TRIPWIRE BYPASS] Pruning spoofed ports on host '{host}'...")
        standard_web_ports = [80, 443, 8080, 8443]
        candidate_ports = [p for p in raw_ports if p in standard_web_ports]

        if not candidate_ports:
            # Fallback to defaults if none were explicitly returned
            candidate_ports = standard_web_ports

        verified_ports = []
        for port in candidate_ports:
            if self._verify_live_http_service(host, port):
                verified_ports.append(port)

        # If none of the standard web ports responded, return at least 80/443
        # for basic vulnerability probing
        if not verified_ports:
            log.warning(
                "[TRIPWIRE BYPASS] No standard web services responded to live HTTP verification. Falling back to 80/443.")
            return [80, 443]

        log.info(
            f"[TRIPWIRE BYPASS] Spoof bypass complete. Pruned {
                len(raw_ports)} fake ports down to verified web: {verified_ports}")
        return verified_ports

    def _grab_raw_banner(self, host: str, port: int) -> str:
        """
        Grab a raw connection banner from a TCP socket.
        """
        if self.ssh:
            # Execute natively in WSL using timeout
            cmd = f"timeout 3 nc -w 2 {host} {port} 2>/dev/null | head -c 200"
            ec, out, _ = self.ssh.execute(cmd)
            if ec == 0 and out.strip():
                return out.strip()
            # Try HTTP request as fallback
            cmd_http = f"curl -sI --max-time 3 http://{host}:{port}/ 2>/dev/null | head -c 200"
            ec_h, out_h, _ = self.ssh.execute(cmd_http)
            if ec_h == 0 and out_h.strip():
                return out_h.strip()
        else:
            # Local socket connection
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((host, port))
                # Send a small return to trigger a banner
                s.sendall(b"\r\n")
                banner = s.recv(200)
                s.close()
                return banner.decode("utf-8", errors="ignore").strip()
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in tripwire_detector.py: {_e}')
        return ""

    def _calculate_jaccard_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaccard similarity index based on character set overlap."""
        if not s1 or not s2:
            return 0.0
        set1, set2 = set(s1), set(s2)
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0.0

    def _verify_live_http_service(self, host: str, port: int) -> bool:
        """Verify that the port actually returns a valid HTTP structure."""
        if self.ssh:
            cmd = f"curl -sI -o /dev/null -w '%{{http_code}}' --max-time 4 http://{host}:{port}/"
            if port == 443 or port == 8443:
                cmd = f"curl -k -sI -o /dev/null -w '%{{http_code}}' --max-time 4 https://{host}:{port}/"
            ec, out, _ = self.ssh.execute(cmd)
            if ec == 0 and out.strip().isdigit():
                code = int(out.strip())
                # Any standard HTTP response code (even 401/403/404/500)
                # confirms a real web server
                return code > 0
        else:
            try:
                import urllib.request
                proto = "https" if port in (443, 8443) else "http"
                # Ignore SSL certificates for local testing
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                urllib.request.urlopen(
                    f"{proto}://{host}:{port}/", timeout=3.0, context=ctx)
                return True
            except Exception as e:
                # If the server returned an error page (e.g. 403 or 404),
                # urllib raises an exception but it is STILL a real service!
                if "HTTP Error" in str(e):
                    return True
        return False
