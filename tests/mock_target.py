#!/usr/bin/env python3
"""
mock_target.py - Zero-dependency HTTP target for Ghostwire V6 integration tests.
Uses Python's built-in http.server instead of Flask.
"""
import http.server
import socketserver
import sqlite3
import os
import json
import urllib.parse

PORT = 9090
DB_PATH = "/tmp/mock_target.db"

# ── InitDB ──


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute(
        "INSERT INTO users (username, password) VALUES ('admin', 'v6_mock_pass')")
    c.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest123')")
    c.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, content TEXT)")
    c.execute(
        "INSERT INTO secrets (content) VALUES ('FLAG{ghostwire_v6_mock_success}')")
    conn.commit()
    conn.close()


class MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress noisy logging during tests

    def _send(self, code: int, content: bytes, ctype: str = "text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            body = b"<h1>Mock Target v1.0</h1><p>Welcome.</p><ul><li><a href=/login>Login</a></li><li><a href=/api/data>API</a></li></ul>"
            self._send(200, body)
        elif path == "/login":
            body = b"<form method=POST><input name=username placeholder=user><input name=password type=password placeholder=pass><button>Login</button></form>"
            self._send(200, body)
        elif path == "/api/data":
            item = qs.get("item", ["default"])[0]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM secrets WHERE id='{item}'"
            try:
                c.execute(query)
                row = c.fetchone()
                if row:
                    self._send(200, json.dumps(
                        {"id": row[0], "content": row[1]}).encode(), "application/json")
                else:
                    self._send(404,
                               json.dumps({"error": "Not found"}).encode(),
                               "application/json")
            except Exception as e:
                self._send(500,
                           json.dumps({"error": str(e)}).encode(),
                           "application/json")
        elif path == "/api/users":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, username FROM users")
            data = {"users": [{"id": r[0], "username": r[1]}
                              for r in c.fetchall()]}
            self._send(200, json.dumps(data).encode(), "application/json")
        elif path == "/admin":
            self._send(403, b"Forbidden")
        elif path == "/.env":
            self._send(
                200,
                b"DB_HOST=localhost\nDB_PASS=ghostwire_mock_123\nSECRET_KEY=mock_secret_123456789")
        elif path == "/robots.txt":
            self._send(
                200, b"User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n")
        elif path == "/api/internal":
            self._send(200, json.dumps(
                {"status": "internal endpoint", "debug": True}).encode(), "application/json")
        elif path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<h2>Search results for: {q}</h2><p>No results found.</p>".encode()
            self._send(200, body)
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode()
            data = urllib.parse.parse_qs(body)
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            try:
                c.execute(query)
                user = c.fetchone()
                if user:
                    response = f"<h2>Welcome, {
                        user[1]}</h2><p>Login successful.</p>"
                else:
                    response = "<h2>Invalid credentials</h2>"
            except Exception as e:
                response = f"<h2>Database error</h2><pre>{e}</pre>"
            self._send(200, response.encode())
        else:
            self._send(405, b"Method Not Allowed")


if __name__ == "__main__":
    init_db()
    with socketserver.TCPServer(("127.0.0.1", PORT), MockHTTPHandler) as httpd:
        print(f"Mock Target starting on http://127.0.0.1:{PORT}")
        httpd.serve_forever()
