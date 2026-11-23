"""Tests for scripts/source-upload.py.

Run from the repository root:
    python3 -m unittest discover -s tests -v

The tests do not contact Launchpad, GitHub or the PPA.  The source-package
integration test uses a tiny local Debian source tree and is skipped when
dpkg-buildpackage is unavailable.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "source-upload.py"


def load_module():
    spec = importlib.util.spec_from_file_location("source_upload", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["source_upload"] = module
    spec.loader.exec_module(module)
    return module


su = load_module()


class FreshApiTests(unittest.TestCase):
    def test_proxy_cannot_reuse_an_old_key_registration_response(self):
        requests = []

        def cached_proxy(request, timeout):
            requests.append(request)
            return io.BytesIO(b'{"entries": []}' if "_fresh=" not in request.full_url
                              else b'{"entries": [{"fingerprint": "registered"}]}')

        with mock.patch.object(su.urllib.request, "urlopen", side_effect=cached_proxy):
            result = su.fetch_json("https://api.launchpad.net/devel/~owner/gpg_keys", 10)
        self.assertEqual(result["entries"][0]["fingerprint"], "registered")
        self.assertEqual(requests[0].get_header("Cache-control"), "no-cache")


class NetworkRetryTests(unittest.TestCase):
    """The PPA front end can answer 503 for minutes, so retries must be patient."""

    URL = ("https://ppa.launchpadcontent.net/oblivionw26/nekobox/ubuntu/"
           "dists/noble/main/source/Sources.gz")
    DELAYS = [5.0, 15.0, 30.0, 60.0, 120.0]

    def http_error(self, code: int):
        fp = io.BytesIO(b"backend unavailable")
        error = urllib.error.HTTPError(self.URL, code, "error", {}, fp)
        return error, fp

    def patched(self, errors, sleeps, log):
        return (
            mock.patch.object(su.urllib.request, "urlopen",
                              side_effect=list(errors)),
            mock.patch.object(su.time, "sleep", side_effect=sleeps.append),
            contextlib.redirect_stderr(log),
        )

    def test_repeated_503_is_retried_then_succeeds(self):
        failures = [self.http_error(503) for _ in range(3)]
        response = mock.MagicMock()
        sleeps: list[float] = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched(
            [error for error, _ in failures] + [response], sleeps, log
        )
        with urlopen as opened, sleep, stderr:
            self.assertIs(su._open(self.URL, 10), response)
        self.assertEqual(opened.call_count, 4)
        self.assertEqual(sleeps, self.DELAYS[:3])
        for _, fp in failures:
            self.assertTrue(fp.closed, "failed HTTP response was left open")
        text = log.getvalue()
        for attempt, delay in enumerate(self.DELAYS[:3], start=1):
            self.assertIn(
                f"warning: {self.URL}: attempt {attempt}/6 failed "
                f"(HTTP 503); retrying in {delay:g}s",
                text,
            )

    def test_503_exhaustion_reports_the_attempt_count(self):
        failures = [self.http_error(503) for _ in range(6)]
        sleeps: list[float] = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched(
            [error for error, _ in failures], sleeps, log
        )
        with urlopen as opened, sleep, stderr:
            with self.assertRaises(su.NetworkError) as caught:
                su._open(self.URL, 10)
        self.assertEqual(opened.call_count, 6)
        self.assertEqual(sleeps, self.DELAYS)
        self.assertIn("after 6 attempts: HTTP 503", str(caught.exception))
        for _, fp in failures:
            self.assertTrue(fp.closed, "failed HTTP response was left open")

    def test_client_error_is_not_retried(self):
        error, fp = self.http_error(403)
        sleeps: list[float] = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched([error], sleeps, log)
        with urlopen as opened, sleep, stderr:
            with self.assertRaises(su.NetworkError):
                su._open(self.URL, 10)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(log.getvalue(), "")
        self.assertTrue(fp.closed)

    def test_missing_url_keeps_immediate_404_semantics(self):
        error, _ = self.http_error(404)
        sleeps: list[float] = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched([error], sleeps, log)
        with urlopen as opened, sleep, stderr:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                su._open(self.URL, 10)
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_download_still_returns_false_for_404(self):
        error, _ = self.http_error(404)
        with tempfile.TemporaryDirectory() as tmpdir:
            destination = Path(tmpdir) / "Sources.gz"
            with mock.patch.object(su.urllib.request, "urlopen", side_effect=[error]), \
                    mock.patch.object(su.time, "sleep"):
                self.assertFalse(su.download(self.URL, destination, 10))
            self.assertFalse(destination.exists())

    def test_network_timeout_is_retried_then_reported(self):
        timeouts = [urllib.error.URLError(TimeoutError("timed out"))
                    for _ in range(2)]
        response = mock.MagicMock()
        sleeps: list[float] = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched(timeouts + [response], sleeps, log)
        with urlopen as opened, sleep, stderr:
            self.assertIs(su._open(self.URL, 10), response)
        self.assertEqual(opened.call_count, 3)
        self.assertEqual(sleeps, self.DELAYS[:2])
        self.assertIn("attempt 1/6 failed (timed out); retrying in 5s",
                      log.getvalue())

        sleeps = []
        log = io.StringIO()
        urlopen, sleep, stderr = self.patched(
            [urllib.error.URLError(TimeoutError("timed out"))] * 6, sleeps, log
        )
        with urlopen as opened, sleep, stderr:
            with self.assertRaises(su.NetworkError) as caught:
                su._open(self.URL, 10)
        self.assertEqual(opened.call_count, 6)
        self.assertEqual(sleeps, self.DELAYS)
        self.assertIn("after 6 attempts: timed out", str(caught.exception))


ENV_TEXT = """# pinned release
UPSTREAM_VERSION=1.0
UPSTREAM_TARBALL=nekobox-unified-source-1.0.tar.xz
UPSTREAM_URL=https://example.invalid/nekobox-unified-source-1.0.tar.xz
UPSTREAM_SHA256={sha}
UPSTREAM_TOP_DIR=nekobox-unified-source-1.0
UPSTREAM_SOURCE_DATE_EPOCH=1700000000
DEBIAN_SOURCE=nekobox
DEBIAN_REVISION=1
DEBIAN_DISTRIBUTION=noble
"""


def write_repo(path: Path, orig_sha: str) -> None:
    (path / "debian").mkdir(parents=True)
    (path / "downloads").mkdir()
    (path / "upstream.env").write_text(
        ENV_TEXT.format(sha=orig_sha), encoding="utf-8"
    )
    (path / "debian" / "changelog").write_text(
        "nekobox (1.0-1) noble; urgency=medium\n\n"
        "  * Test entry.\n\n"
        " -- Test <test@example.invalid>  Mon, 01 Jan 2024 00:00:00 +0000\n",
        encoding="utf-8",
    )


def make_orig(path: Path) -> Path:
    orig = path / "nekobox_1.0.orig.tar.xz"
    with tarfile.open(orig, "w:xz") as archive:
        for name, data in {
            "nekobox-1.0/README": b"test\n",
            "nekobox-1.0/CMakeLists.txt": b"cmake_minimum_required(VERSION 3.16)\n",
            "nekobox-1.0/core/server/go.mod": b"module example.invalid/core\n",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return orig


def make_source_tree(path: Path) -> Path:
    tree = path / "nekobox-1.0"
    (tree / "debian" / "source").mkdir(parents=True)
    (tree / "core" / "server").mkdir(parents=True)
    (tree / "debian" / "control").write_text(
        "Source: nekobox\n"
        "Section: net\n"
        "Priority: optional\n"
        "Maintainer: Test <test@example.invalid>\n"
        "Standards-Version: 4.7.0\n"
        "Build-Depends: debhelper-compat (= 13)\n"
        "Rules-Requires-Root: no\n"
        "\n"
        "Package: nekobox\n"
        "Architecture: any\n"
        "Depends: ${misc:Depends}\n"
        "Description: test package\n",
        encoding="utf-8",
    )
    (tree / "debian" / "rules").write_text(
        "#!/usr/bin/make -f\n%:\n\tdh $@\n", encoding="utf-8"
    )
    (tree / "debian" / "rules").chmod(0o755)
    (tree / "debian" / "source" / "format").write_text(
        "3.0 (quilt)\n", encoding="utf-8"
    )
    (tree / "debian" / "changelog").write_text(
        "nekobox (1.0-1~ubuntu24.04.1) noble; urgency=medium\n\n"
        "  * Test entry.\n\n"
        " -- Test <test@example.invalid>  Mon, 01 Jan 2024 00:00:00 +0000\n",
        encoding="utf-8",
    )
    (tree / "README").write_text("test\n", encoding="utf-8")
    (tree / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\n", encoding="utf-8"
    )
    (tree / "core" / "server" / "go.mod").write_text(
        "module example.invalid/core\n", encoding="utf-8"
    )
    return tree


def plan_for(repo: Path, needed: bool = True) -> dict:
    return {
        "schema_version": su.SCHEMA_VERSION,
        "version": "1.0",
        "revision": "1",
        "base_version": "1.0-1",
        "ppa": su.PPA_BASE,
        "orig": None,
        "series": {
            "noble": {
                "series": "noble",
                "base": "ubuntu:24.04",
                "target_version": "1.0-1~ubuntu24.04.1",
                "needed": needed,
                "action": "upload" if needed else "skip",
                "reason": "test",
                "source_status": None,
            }
        },
        "needed_series": ["noble"] if needed else [],
        "matrix": [
            {
                "series": "noble",
                "base": "ubuntu:24.04",
                "target_version": "1.0-1~ubuntu24.04.1",
                "needed": needed,
            }
        ],
        "publish_matrix": [],
    }


class UnitTests(unittest.TestCase):
    def test_target_version_uses_series_suffix(self):
        self.assertEqual(
            su.target_version("5.11.28.3-2~ppa1", "noble"),
            "5.11.28.3-2~ppa1~ubuntu24.04.1",
        )
        self.assertEqual(
            su.target_version("5.11.28.3-2~ppa1", "stonking"),
            "5.11.28.3-2~ppa1~ubuntu26.10.1",
        )
        with self.assertRaises(su.UsageError):
            su.target_version("1", "unknown")

    def test_rewrite_changelog_only_changes_first_entry(self):
        text = (
            "nekobox (1.0-1) resolute; urgency=medium\n\n"
            "  * Old.\n\n"
            " -- A <a@example.invalid>  Mon, 01 Jan 2024 00:00:00 +0000\n\n"
            "nekobox (0.9-1) resolute; urgency=medium\n\n"
            "  * Older.\n\n"
            " -- A <a@example.invalid>  Sun, 31 Dec 2023 00:00:00 +0000\n"
        )
        updated = su.rewrite_changelog(
            text, "1.0-2~ppa1~ubuntu24.04.1", "noble"
        )
        self.assertTrue(
            updated.startswith(
                "nekobox (1.0-2~ppa1~ubuntu24.04.1) noble; urgency=medium\n"
            )
        )
        self.assertIn("  * Old.", updated)
        self.assertIn("nekobox (0.9-1) resolute", updated)

    def test_archived_orig_parsing_uses_strong_digest(self):
        dsc = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: nekobox
Version: 1.0-2~ppa1~ubuntu24.04.1
Checksums-Sha256:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123 nekobox_1.0.orig.tar.gz
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 45 nekobox_1.0-2~ppa1~ubuntu24.04.1.debian.tar.xz

-----BEGIN PGP SIGNATURE-----
fake
-----END PGP SIGNATURE-----
"""
        result = su.orig_from_dsc(dsc)
        self.assertEqual(result["name"], "nekobox_1.0.orig.tar.gz")
        self.assertEqual(result["size"], 123)
        self.assertEqual(result["sha256"], "a" * 64)

    def test_merge_file_entries_rejects_inconsistent_sizes(self):
        with self.assertRaises(su.SourceUploadError):
            su.merge_file_entries(
                {
                    "Files": " " * 0 + "a" * 32 + " 1 x.dsc",
                    "Checksums-Sha256": "b" * 64 + " 2 x.dsc",
                }
            )

    def test_tree_manifest_includes_permission_bits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "script.sh"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            script.chmod(0o644)
            first = su.tree_manifest(root)
            script.chmod(0o755)
            second = su.tree_manifest(root)
        self.assertNotEqual(first, second)
        self.assertIn("0644", first)
        self.assertIn("0755", second)

    def test_verify_signature_checks_expected_signer(self):
        fingerprint = "AB" * 20
        completed = subprocess.CompletedProcess(
            args=["gpg"], returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {fingerprint} 2026-01-01 0 0 5 0 22 10 00 {fingerprint}\n",
            stderr="",
        )
        with mock.patch.object(su.subprocess, "run", return_value=completed):
            self.assertEqual(
                su.verify_signature(Path("x.changes"), fingerprint[-16:]),
                fingerprint,
            )
            with self.assertRaises(su.SourceUploadError):
                su.verify_signature(Path("x.changes"), "CD" * 20)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        write_repo(self.repo, "0" * 64)

    def tearDown(self):
        self.tmp.cleanup()

    def published(self, version: str, status: str = "Published",
                  series: str = "noble") -> dict:
        return {
            "source_package_version": version,
            "status": status,
            "distro_series_link": f"https://api.launchpad.net/devel/ubuntu/{series}",
        }

    def test_all_series_published_needs_nothing_but_keeps_validation_matrix(self):
        with mock.patch.object(su, "launchpad_sources") as sources:
            sources.return_value = [
                self.published("1.0-1~ubuntu24.04.1", series="noble"),
                self.published("1.0-1~ubuntu26.04.1", series="resolute"),
                self.published("1.0-1~ubuntu26.10.1", series="stonking"),
            ]
            result = su.plan(self.repo, ["noble", "resolute", "stonking"], 1)
        self.assertEqual(result["needed_series"], [])
        self.assertEqual(result["publish_matrix"], [])
        self.assertEqual(len(result["matrix"]), 3)
        self.assertTrue(all(not item["needed"] for item in result["matrix"]))
        self.assertTrue(
            all(entry["action"] == "skip" for entry in result["series"].values())
        )

    def test_one_missing_series_is_the_only_publish_target(self):
        priors = {
            "name": "nekobox_1.0.orig.tar.gz",
            "size": 10,
            "sha256": "c" * 64,
            "origin": "archive",
        }
        with mock.patch.object(su, "launchpad_sources") as sources, \
                mock.patch.object(su, "archived_orig") as archived:
            sources.return_value = [
                self.published("1.0-1~ubuntu26.04.1", series="resolute"),
                self.published("1.0-1~ubuntu26.10.1", series="stonking"),
            ]
            archived.return_value = priors
            result = su.plan(
                self.repo, ["noble", "resolute", "stonking"], 1
            )
        self.assertEqual(result["needed_series"], ["noble"])
        self.assertEqual([item["series"] for item in result["publish_matrix"]],
                         ["noble"])
        self.assertEqual(result["orig"], priors)
        self.assertEqual(len(result["matrix"]), 3)

    def test_candidate_release_needs_every_series(self):
        with mock.patch.object(su, "launchpad_sources") as sources:
            result = su.plan(
                self.repo, ["noble", "resolute"], 1,
                version="1.1", revision="1",
            )
        sources.assert_not_called()
        self.assertEqual(result["needed_series"], ["noble", "resolute"])
        self.assertEqual(result["series"]["noble"]["target_version"],
                         "1.1-1~ubuntu24.04.1")
        self.assertEqual(result["orig"]["origin"], "upstream")

    def test_upstream_orig_is_selected_when_no_archive_source_exists(self):
        upstream = self.repo / "downloads" / "nekobox-unified-source-1.0.tar.xz"
        upstream.write_bytes(b"upstream bytes")
        sha = su.sha256_file(upstream)
        (self.repo / "upstream.env").write_text(
            ENV_TEXT.format(sha=sha), encoding="utf-8"
        )
        env = su.read_env(self.repo / "upstream.env")
        with mock.patch.object(su, "archived_orig", return_value=None):
            meta = su._orig_for_prepare(
                self.repo, env, "1.0", self.repo / "build", 1
            )
        self.assertEqual(meta["origin"], "upstream")
        self.assertEqual(meta["sha256"], sha)
        self.assertEqual(meta["path"], upstream)

    def test_inactive_exact_version_is_not_reuploaded(self):
        with mock.patch.object(su, "launchpad_sources") as sources:
            sources.return_value = [
                self.published("1.0-1~ubuntu24.04.1", "Superseded"),
                self.published("1.0-1~ubuntu26.04.1"),
                self.published("1.0-1~ubuntu26.10.1"),
            ]
            result = su.plan(self.repo, ["noble"], 1)
        self.assertFalse(result["series"]["noble"]["needed"])
        self.assertEqual(result["series"]["noble"]["source_status"], "Superseded")

    def test_pending_blocks_archived_orig_reuse(self):
        with mock.patch.object(su, "launchpad_sources") as sources:
            sources.return_value = [
                self.published("1.0-1~ubuntu24.04.1", "Pending"),
            ]
            with self.assertRaises(su.SourceUploadError) as caught:
                su.archived_orig("1.0", 1)
        self.assertIn("no Published source", str(caught.exception))

    def test_deleted_only_has_no_immutable_orig(self):
        with mock.patch.object(su, "launchpad_sources") as sources:
            sources.return_value = [
                self.published("1.0-1~ubuntu24.04.1", "Deleted"),
            ]
            self.assertIsNone(su.archived_orig("1.0", 1))


class PrepareAndBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.orig = make_orig(self.repo)
        self.orig_sha = su.sha256_file(self.orig)
        write_repo(self.repo, self.orig_sha)
        self.tree = make_source_tree(self.repo / "build")
        shutil.copy2(
            self.orig, self.repo / "build" / "nekobox_1.0.orig.tar.xz"
        )
        fake = self.repo / "scripts" / "fake-prepare.sh"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        self.prepare_script = fake
        self.orig_override = {
            "origin": "upstream",
            "path": self.orig,
            "name": "nekobox_1.0.orig.tar.xz",
            "sha256": self.orig_sha,
            "size": self.orig.stat().st_size,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_keeps_unneeded_series_for_validation(self):
        result = su.prepare(
            self.repo, plan_for(self.repo, needed=False), "noble", 1,
            prepare_script=self.prepare_script,
            orig_override=self.orig_override,
        )
        self.assertFalse(result["needed"])
        manifest = json.loads(
            (self.repo / "build" / "upload" / "noble" / "prepare.json")
            .read_text(encoding="utf-8")
        )
        self.assertFalse(manifest["needed"])
        self.assertEqual(manifest["target_version"], "1.0-1~ubuntu24.04.1")
        self.assertEqual(manifest["orig"]["sha256"], self.orig_sha)
        self.assertTrue(manifest["debian_manifest"])
        changelog = Path(manifest["tree"]) / "debian" / "changelog"
        self.assertTrue(
            changelog.read_text(encoding="utf-8").startswith(
                "nekobox (1.0-1~ubuntu24.04.1) noble;"
            )
        )

    def test_prepare_records_the_actual_generated_orig_for_upstream(self):
        repack = self.repo / "scripts" / "repack.sh"
        repack.write_text(
            "#!/bin/sh\nset -e\nprintf 'repacked bytes\\n' "
            "> build/nekobox_1.0.orig.tar.xz\n",
            encoding="utf-8",
        )
        repack.chmod(0o755)
        result = su.prepare(
            self.repo, plan_for(self.repo, needed=True), "noble", 1,
            prepare_script=repack,
            orig_override=self.orig_override,
        )
        actual = su.sha256_file(self.repo / "build" / "nekobox_1.0.orig.tar.xz")
        self.assertNotEqual(actual, self.orig_sha)
        self.assertEqual(result["orig"]["sha256"], actual)
        manifest = json.loads(
            (self.repo / "build" / "upload" / "noble" / "prepare.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["orig"]["sha256"], actual)
        self.assertEqual(manifest["orig"]["origin"], "upstream")

    @unittest.skipUnless(
        shutil.which("dpkg-buildpackage") and shutil.which("dpkg-source"),
        "dpkg-dev is required for the source-package integration test",
    )
    def test_unsigned_sign_builds_and_roundtrips_the_prepared_tree(self):
        su.prepare(
            self.repo, plan_for(self.repo, needed=False), "noble", 1,
            prepare_script=self.prepare_script,
            orig_override=self.orig_override,
        )
        result = su.sign(
            self.repo, plan_for(self.repo, needed=False), "noble",
            unsigned=True,
        )
        self.assertTrue(result["unsigned"])
        self.assertFalse(result["signature_verified"])
        self.assertEqual(result["action"], "validated-unsigned")
        changes = Path(result["changes"])
        self.assertTrue(changes.is_file())
        text = changes.read_text(encoding="utf-8")
        self.assertIn("Architecture: source", text)
        self.assertIn("Distribution: noble", text)
        self.assertIn("Version: 1.0-1~ubuntu24.04.1", text)
        self.assertIn("nekobox_1.0.orig.tar.xz", text)
        self.assertNotRegex(text, r"(?m)^ .*\.deb$")

        original = changes.read_text(encoding="utf-8")
        changes.write_text(
            original.replace("Architecture: source", "Architecture: amd64"),
            encoding="utf-8",
        )
        with self.assertRaises(su.SourceUploadError):
            su.verify_changes(
                changes,
                {
                    "series": "noble",
                    "target_version": "1.0-1~ubuntu24.04.1",
                    "orig": self.orig_override,
                },
            )


class PrepareSourceScriptTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("dpkg-source") and shutil.which("tar"),
        "dpkg-source is required for the prepare-source regression",
    )
    def test_orig_file_inside_build_is_not_deleted_before_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "scripts").mkdir()
            (repo / "debian" / "source").mkdir(parents=True)
            (repo / "build").mkdir()
            shutil.copy2(
                ROOT / "scripts" / "prepare-source.sh",
                repo / "scripts" / "prepare-source.sh",
            )
            (repo / "upstream.env").write_text(
                "UPSTREAM_VERSION=1.0\n"
                "UPSTREAM_TARBALL=upstream-1.0.tar.xz\n"
                "UPSTREAM_URL=https://example.invalid/upstream-1.0.tar.xz\n"
                "UPSTREAM_SHA256=" + "0" * 64 + "\n"
                "UPSTREAM_TOP_DIR=upstream-1.0\n"
                "UPSTREAM_SOURCE_DATE_EPOCH=1700000000\n"
                "DEBIAN_SOURCE=nekobox\n"
                "DEBIAN_REVISION=1\n"
                "DEBIAN_DISTRIBUTION=noble\n",
                encoding="utf-8",
            )
            (repo / "debian" / "control").write_text(
                "Source: nekobox\nSection: net\nPriority: optional\n"
                "Maintainer: Test <test@example.invalid>\n"
                "Standards-Version: 4.7.0\n"
                "Build-Depends: debhelper-compat (= 13)\n\n"
                "Package: nekobox\nArchitecture: any\n"
                "Depends: ${misc:Depends}\nDescription: test\n",
                encoding="utf-8",
            )
            (repo / "debian" / "rules").write_text(
                "#!/usr/bin/make -f\n%:\n\tdh $@\n", encoding="utf-8"
            )
            (repo / "debian" / "rules").chmod(0o755)
            (repo / "debian" / "source" / "format").write_text(
                "3.0 (quilt)\n", encoding="utf-8"
            )
            (repo / "debian" / "changelog").write_text(
                "nekobox (1.0-1) noble; urgency=medium\n\n"
                "  * Test.\n\n"
                " -- Test <test@example.invalid>  Mon, 01 Jan 2024 00:00:00 +0000\n",
                encoding="utf-8",
            )
            orig = repo / "build" / "nekobox_1.0.orig.tar.gz"
            with tarfile.open(orig, "w:gz") as archive:
                for name, data in {
                    "nekobox-1.0/README": b"test\n",
                    "nekobox-1.0/CMakeLists.txt": b"cmake_minimum_required(VERSION 3.16)\n",
                    "nekobox-1.0/core/server/go.mod": b"module example.invalid/core\n",
                }.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            digest = su.sha256_file(orig)
            proc = subprocess.run(
                [
                    str(repo / "scripts" / "prepare-source.sh"),
                    "--orig-file", str(orig),
                    "--orig-sha256", digest,
                ],
                cwd=repo, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertTrue(orig.is_file(), "the verified input was deleted")
            dsc = repo / "build" / "nekobox_1.0-1.dsc"
            self.assertTrue(dsc.is_file())
            self.assertIn("nekobox_1.0.orig.tar.gz", dsc.read_text(encoding="utf-8"))
            self.assertEqual(
                list((repo / "build").glob(".archived-orig.*")), []
            )


class UploadTests(unittest.TestCase):
    def test_upload_rejects_a_stale_plan_before_any_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            work = repo / "build" / "upload" / "noble"
            work.mkdir(parents=True)
            source = {
                "series": "noble",
                "distribution": "noble",
                "version": "1.0",
                "base_version": "1.0-1",
                "target_version": "1.0-1~ubuntu24.04.1",
                "needed": True,
                "unsigned": False,
                "signature_verified": True,
                "signing_key": "A" * 40,
                "orig": {"name": "nekobox_1.0.orig.tar.xz", "sha256": "b" * 64},
                "changes": str(work / "x.changes"),
                "dsc": str(work / "x.dsc"),
            }
            (work / "source.json").write_text(json.dumps(source), encoding="utf-8")
            plan = plan_for(repo, needed=True)
            plan["series"]["noble"]["target_version"] = "9.9-1~ubuntu24.04.1"
            with mock.patch.object(su, "launchpad_status") as status:
                with self.assertRaises(su.UsageError):
                    su.upload(repo, plan, "noble", dry_run=True)
            status.assert_not_called()


class KeyPreflightTests(unittest.TestCase):
    def test_status_prefers_active_record(self):
        entry = {
            "source_package_version": "1.0-1~ubuntu24.04.1",
            "distro_series_link": "https://api.launchpad.net/devel/ubuntu/noble",
        }
        with mock.patch.object(su, "launchpad_sources", return_value=[
            dict(entry, status="Superseded"),
            dict(entry, status="Pending"),
        ]):
            self.assertEqual(
                su.launchpad_status("noble", "1.0-1~ubuntu24.04.1", 1),
                "Pending",
            )

    def test_missing_launchpad_keys_is_a_clear_failure(self):
        with mock.patch.object(su, "fetch_json", return_value={"entries": []}):
            with self.assertRaises(su.SourceUploadError) as caught:
                su.preflight_key("A" * 40, 1)
        self.assertIn("no registered GPG key", str(caught.exception))

    def test_registered_fingerprint_passes(self):
        fingerprint = "AB" * 20
        with mock.patch.object(
            su, "fetch_json",
            return_value={"entries": [{"fingerprint": fingerprint, "active": True}]},
        ):
            result = su.preflight_key(fingerprint, 1)
        self.assertEqual(result["fingerprint"], fingerprint)


if __name__ == "__main__":
    unittest.main()
