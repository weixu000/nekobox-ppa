import importlib.util
import io
import os
from email.message import Message
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.request import Request

spec = importlib.util.spec_from_file_location(
    "upstream_auth", Path(__file__).parents[1] / "scripts/check-upstream.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class AuthTests(unittest.TestCase):
    def request_for(self, url):
        response = io.BytesIO(b"[]")
        response.headers = Message()
        with patch.dict(os.environ, {"GH_TOKEN": "fixture-token"}):
            with patch.object(checker.urllib.request, "build_opener") as factory:
                factory.return_value.open.return_value = response
                self.assertEqual(checker.fetch_json(url, 5, 0), [])
                return factory.return_value.open.call_args.args[0]

    def test_github_api_uses_runner_token(self):
        request = self.request_for("https://api.github.com/repos/example/project/releases")
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-token")

    def test_override_api_does_not_receive_token(self):
        for url in ("http://api.github.com/releases", "https://example.org/releases"):
            self.assertIsNone(self.request_for(url).get_header("Authorization"))

    def test_redirect_cannot_leak_token(self):
        request = Request("https://api.github.com/releases",
                          headers={"Authorization": "Bearer fixture-token"})
        with self.assertRaises(checker.NetworkError):
            checker.GitHubRedirectHandler().redirect_request(
                request, None, 302, "Found", {}, "https://example.org/releases"
            )
