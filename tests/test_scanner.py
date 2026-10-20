import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCANNER = Path(__file__).resolve().parent.parent / "scanner.py"


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Set-Cookie", "hop=1")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "session=abc123")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>test</html>")

    def log_message(self, *args):
        pass


def run_scan(*args, confirm=True):
    cmd = [sys.executable, str(SCANNER), *args]
    if confirm:
        cmd.append("--i-own-this")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_refuses_without_flag(self):
        r = run_scan("example.com", confirm=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Refused", r.stderr)

    def test_http_only_finding(self):
        r = run_scan(self.url)
        self.assertEqual(r.returncode, 1)
        self.assertIn("[High] Site is served over HTTP only", r.stdout)

    def test_cookie_set_on_redirect(self):
        r = run_scan(self.url)
        self.assertIn("Cookie 'hop' has no Secure flag", r.stdout)
        self.assertIn("Cookie 'session' has no Secure flag", r.stdout)

    def test_server_version_leak(self):
        r = run_scan(self.url)
        self.assertIn("Server header shows version: Apache/2.4.41", r.stdout)

    def test_no_admin_false_positive(self):
        r = run_scan(self.url)
        self.assertNotIn("/admin", r.stdout)

    def test_unresolvable_host_exit_code(self):
        r = run_scan("nonexistent-host-12345.invalid")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("# sitecheck report", r.stdout)

    def test_summary_counts(self):
        r = run_scan(self.url)
        self.assertIn("Findings: 1 High, 6 Medium, 5 Low", r.stdout)


if __name__ == "__main__":
    unittest.main()
