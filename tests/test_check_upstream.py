"""Tests for scripts/check-upstream.py.

Run from the repository root:
    python3 -m unittest discover -s tests -v

The tests only use saved JSON payloads and a loopback connection that is
refused; they never contact GitHub or download a release.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-upstream.py"
DEFAULT_SHA = "a" * 64
DEFAULT_DIGEST = "sha256:" + DEFAULT_SHA
MISSING = object()


def release(
    version: str,
    *,
    draft: bool = False,
    prerelease: bool = False,
    source: bool = True,
    digest: object = DEFAULT_DIGEST,
    published: str = "2026-09-01T00:00:00Z",
) -> dict:
    assets = []
    if source:
        asset = {
            "name": f"nekobox-unified-source-{version}.tar.xz",
            "browser_download_url": (
                "https://github.com/qr243vbi/nekobox/releases/download/"
                f"{version}/nekobox-unified-source-{version}.tar.xz"
            ),
            "size": 12_480_000,
        }
        if digest is not MISSING:
            asset["digest"] = digest
        assets.append(asset)
    return {
        "tag_name": version,
        "name": version,
        "draft": draft,
        "prerelease": prerelease,
        "published_at": published,
        "assets": assets,
    }


def env_text(version: str) -> str:
    return (
        "# test fixture\n"
        f"UPSTREAM_VERSION={version}\n"
        f"UPSTREAM_TARBALL=nekobox-unified-source-{version}.tar.xz\n"
        "UPSTREAM_URL=https://github.com/qr243vbi/nekobox/releases/download/"
        f"{version}/nekobox-unified-source-{version}.tar.xz\n"
        f"UPSTREAM_SHA256={DEFAULT_SHA}\n"
        "UPSTREAM_TOP_DIR=nekobox-unified-source-"
        f"{version}\n"
        "UPSTREAM_SOURCE_DATE_EPOCH=1787770472\n"
    )


class CheckUpstreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("dpkg") is None:
            raise unittest.SkipTest("dpkg is required for version comparison")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def write_env(self, version: str) -> Path:
        path = self.tmp / "upstream.env"
        path.write_text(env_text(version), encoding="utf-8")
        return path

    def run_check(
        self,
        payload: object,
        current: str,
        *extra_args: str,
        raw_fixture: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        env_path = self.write_env(current)
        fixture = self.tmp / "releases.json"
        if raw_fixture is not None:
            fixture.write_text(raw_fixture, encoding="utf-8")
        else:
            fixture.write_text(json.dumps(payload), encoding="utf-8")
        child_env = os.environ.copy()
        child_env.update(
            {
                "NO_PROXY": "*",
                "no_proxy": "*",
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "http_proxy": "",
                "https_proxy": "",
            }
        )
        if extra_env:
            child_env.update(extra_env)
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--env",
                str(env_path),
                "--releases-json",
                str(fixture),
                *extra_args,
            ],
            cwd=ROOT,
            env=child_env,
            text=True,
            capture_output=True,
        )
        data = json.loads(proc.stdout)
        return proc, data

    # ---------------------------------------------------------- candidates

    def test_newer_stable_with_asset_is_candidate_and_prerelease_ignored(self):
        proc, data = self.run_check(
            [
                release("5.11.28.99", prerelease=True),
                release("5.11.29.0", draft=True),
                release("5.11.28.4"),
            ],
            "5.11.28.3",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "update-available")
        candidate = data["candidate"]
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["version"], "5.11.28.4")
        self.assertEqual(candidate["tag"], "5.11.28.4")
        self.assertEqual(
            candidate["asset_name"], "nekobox-unified-source-5.11.28.4.tar.xz"
        )
        self.assertTrue(candidate["asset_url"].startswith("https://github.com/"))
        self.assertEqual(candidate["digest"], "sha256:" + DEFAULT_SHA)
        self.assertEqual(candidate["released_at"], "2026-09-01T00:00:00Z")
        self.assertEqual(data["current"]["version"], "5.11.28.3")
        self.assertEqual(data["skipped"], [])

    def test_version_comparison_is_numeric_not_lexical(self):
        proc, data = self.run_check(
            [release("5.11.28.10")],
            "5.11.28.9",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "update-available")
        self.assertEqual(data["candidate"]["version"], "5.11.28.10")

    def test_no_update_when_pin_is_newest_stable(self):
        proc, data = self.run_check(
            [release("5.11.28.3"), release("5.11.28.2")],
            "5.11.28.3",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "up-to-date")
        self.assertIsNone(data["candidate"])

    def test_older_release_is_not_a_downgrade(self):
        proc, data = self.run_check(
            [release("5.11.28.2"), release("5.11.27.9")],
            "5.11.28.3",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "up-to-date")
        self.assertIsNone(data["candidate"])

    # ------------------------------------------------------------- assets

    def test_missing_source_asset_is_skipped_and_reported(self):
        proc, data = self.run_check(
            [
                release("5.11.28.5", source=False),
                release("5.11.28.4"),
            ],
            "5.11.28.3",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "update-available")
        self.assertEqual(data["candidate"]["version"], "5.11.28.4")
        self.assertEqual(
            data["skipped"],
            [
                {
                    "tag": "5.11.28.5",
                    "version": "5.11.28.5",
                    "reason": "missing-source-asset",
                }
            ],
        )
        self.assertIn("missing source asset", proc.stderr)

    def test_newer_stable_without_asset_is_not_reported_as_update(self):
        proc, data = self.run_check(
            [release("5.11.28.5", source=False)],
            "5.11.28.3",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(data["status"], "up-to-date")
        self.assertIsNone(data["candidate"])
        self.assertEqual(len(data["skipped"]), 1)
        self.assertEqual(data["skipped"][0]["reason"], "missing-source-asset")

    def test_digest_may_be_null_or_absent(self):
        for digest in (None, MISSING):
            with self.subTest(digest=digest):
                proc, data = self.run_check(
                    [release("5.11.28.4", digest=digest)],
                    "5.11.28.3",
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(data["status"], "update-available")
                self.assertIsNone(data["candidate"]["digest"])
                self.assertTrue(
                    data["verification"]["digest_is_not_verification"]
                )
                self.assertIn("SHA-256", data["verification"]["required"])

    # ------------------------------------------------------------- errors

    def test_malformed_responses_have_distinct_exit_code(self):
        cases = {
            "object instead of array": {"message": "Not Found"},
            "release without tag": [{"assets": []}],
            "non-boolean prerelease": [
                {"tag_name": "5.11.28.4", "prerelease": "false", "assets": []}
            ],
            "missing draft/prerelease flags": [
                {"tag_name": "5.11.28.4", "assets": []}
            ],
        }
        for label, payload in cases.items():
            with self.subTest(label):
                proc, data = self.run_check(payload, "5.11.28.3")
                self.assertEqual(proc.returncode, 4, proc.stderr)
                self.assertEqual(data["status"], "error")
                self.assertEqual(data["error"]["kind"], "invalid-response")

    def test_invalid_json_fixture_has_exit_4(self):
        proc, data = self.run_check(
            None, "5.11.28.3", raw_fixture="{not json"
        )
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(data["error"]["kind"], "invalid-response")

    def test_network_failure_has_distinct_exit_code_3(self):
        env_path = self.write_env("5.11.28.3")
        child_env = os.environ.copy()
        child_env.update(
            {
                "NO_PROXY": "*",
                "no_proxy": "*",
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "http_proxy": "",
                "https_proxy": "",
            }
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--env",
                str(env_path),
                "--api-url",
                "http://127.0.0.1:1/releases",
                "--timeout",
                "1",
                "--retries",
                "0",
            ],
            cwd=ROOT,
            env=child_env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 3, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["error"]["kind"], "network")
        self.assertIn("cannot reach", data["error"]["message"])

    def test_bad_config_has_exit_code_2(self):
        proc, data = self.run_check([release("5.11.28.4")], "not a version")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(data["error"]["kind"], "config")


if __name__ == "__main__":
    unittest.main()
