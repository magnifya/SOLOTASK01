"""端到端测试：HTTP 接口、CLI、租户隔离与重启持久化。"""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kms.server import make_handler
from kms.service import KeyService
from kms.store import KeyStore


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp()
        cls.service = KeyService(KeyStore(cls.data_dir))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.service))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, body=None):
        request = urllib.request.Request(
            self.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_full_flow(self):
        status, body = self.req("POST", "/v1/keys", {
            "tenant_id": "acme", "algorithm": "RSA2048", "label": "signing"})
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"key_id", "algorithm", "public_key"})
        self.assertTrue(body["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))
        key_id = body["key_id"]

        status, body = self.req("POST", "/v1/keys", {
            "tenant_id": "acme", "algorithm": "AES256", "label": "enc"})
        self.assertEqual(status, 201)
        self.assertIsNone(body["public_key"])

        status, got = self.req("GET", f"/v1/keys/{key_id}?tenant_id=acme")
        self.assertEqual(status, 200)
        self.assertEqual(set(got), {"algorithm", "label", "created_at", "public_key"})
        self.assertEqual(got["label"], "signing")
        self.assertNotIn("private", json.dumps(got).lower())

        # 租户隔离：其他租户查同一 key_id 一律 404
        status, _ = self.req("GET", f"/v1/keys/{key_id}?tenant_id=other")
        self.assertEqual(status, 404)

        # 重启后仍可查到，created_at 不变
        service2 = KeyService(KeyStore(self.data_dir))
        view = service2.get("acme", key_id)
        self.assertIsNotNone(view)
        self.assertEqual(view["created_at"], got["created_at"])

    def test_validation_errors_name_the_field(self):
        for payload, field in [
            ({"algorithm": "AES256", "label": "x"}, "tenant_id"),
            ({"tenant_id": "t", "label": "x"}, "algorithm"),
            ({"tenant_id": "t", "algorithm": "AES256"}, "label"),
            ({"tenant_id": "t", "algorithm": "AES128", "label": "x"}, "algorithm"),
        ]:
            status, body = self.req("POST", "/v1/keys", payload)
            self.assertEqual(status, 400, payload)
            self.assertIn(field, body["error"])

        status, body = self.req("GET", "/v1/keys/whatever")
        self.assertEqual(status, 400)
        self.assertIn("tenant_id", body["error"])


class CliCase(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp()

    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "kms", "--data-dir", self.data_dir, *argv],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent))

    def test_gen_and_show(self):
        gen = self.run_cli("gen", "--tenant-id", "acme",
                           "--algorithm", "AES256", "--label", "enc")
        self.assertEqual(gen.returncode, 0, gen.stderr)
        created = json.loads(gen.stdout)
        self.assertEqual(set(created), {"key_id", "algorithm", "public_key"})
        self.assertIsNone(created["public_key"])

        show = self.run_cli("show", "--tenant-id", "acme",
                            "--key-id", created["key_id"])
        self.assertEqual(show.returncode, 0, show.stderr)
        view = json.loads(show.stdout)
        self.assertEqual(set(view), {"algorithm", "label", "created_at", "public_key"})
        self.assertEqual(view["label"], "enc")

        other = self.run_cli("show", "--tenant-id", "other",
                             "--key-id", created["key_id"])
        self.assertNotEqual(other.returncode, 0)

        bad = self.run_cli("gen", "--tenant-id", "acme",
                           "--algorithm", "AES128", "--label", "x")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("algorithm", bad.stderr)


if __name__ == "__main__":
    unittest.main()
